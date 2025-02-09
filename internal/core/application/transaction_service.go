package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/equitas-foundation/bamp-ocean/internal/core/domain"
	"github.com/equitas-foundation/bamp-ocean/internal/core/ports"
	wallet "github.com/equitas-foundation/bamp-ocean/pkg/wallet"
	multisig "github.com/equitas-foundation/bamp-ocean/pkg/wallet/multi-sig"
	singlesig "github.com/equitas-foundation/bamp-ocean/pkg/wallet/single-sig"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/psetv2"
	"github.com/vulpemventures/go-elements/transaction"
)

var (
	ErrForbiddenUnlockedInputs = fmt.Errorf(
		"the utxos used within 'external' transactions must be coming from a " +
			"wallet's coin selection so that they can be temporary locked and " +
			"prevent to accidentally double spending them",
	)
)

// TransactionService is responsible for operations related to one or more
// accounts:
//   - Get info about a wallet-related transaction.
//   - Select a subset of the utxos of an existing account to cover a target amount. The selected utxos will be temporary locked to prevent double spending them.
//   - Estimate the fee amount for a transation composed by X inputs and Y outputs. It is required that the inputs owned by the wallet are locked utxos.
//   - Sign a raw transaction (in hex format). It is required that the inputs of the tx owned by the wallet are locked utxos.
//   - Broadcast a raw transaction (in hex format). It is required that the inputs of the tx owned by the wallet are locked utxos.
//   - Create a partial transaction (v2) given a list of inputs and outputs. It is required that the inputs of the tx owned by the wallet are locked utxos.
//   - Add inputs or outputs to partial transaction (v2). It is required that the inputs of the tx owned by the wallet are locked utxos.
//   - Blind a partial transaction (v2) either as non-last or last blinder. It is required that the inputs of the tx owned by the wallet are locked utxos.
//   - Sign a partial transaction (v2). It is required that the inputs of the tx owned by the wallet are locked utxos.
//   - Craft a finalized transaction to transfer some funds from an existing account to somewhere else, given a list of outputs.
//
// The service registers 1 handler for the following utxo event:
//   - domain.UtxoLocked - whenever one or more utxos are locked, the service spawns a so-called unlocker, a goroutine wating for X seconds before unlocking them if necessary. The operation is just skipped if the utxos have been spent meanwhile.
//
// The service guarantees that any locked utxo is eventually unlocked ASAP
// after the waiting time expires.
// Therefore, at startup, it makes sure to unlock any still-locked utxo that
// can be unlocked, and to spawn the required numnber of unlockers for those
// whose waiting time didn't expire yet.
type TransactionService struct {
	repoManager        ports.RepoManager
	bcScanner          ports.BlockchainScanner
	cosigner           ports.Cosigner
	network            *network.Network
	rootPath           string
	utxoExpiryDuration time.Duration

	log func(format string, a ...interface{})
}

func NewTransactionService(
	repoManager ports.RepoManager, bcScanner ports.BlockchainScanner,
	cosigner ports.Cosigner,
	net *network.Network, rootPath string, utxoExpiryDuration time.Duration,
) *TransactionService {
	logFn := func(format string, a ...interface{}) {
		format = fmt.Sprintf("transaction service: %s", format)
		log.Debugf(format, a...)
	}
	svc := &TransactionService{
		repoManager, bcScanner, cosigner, net, rootPath, utxoExpiryDuration, logFn,
	}
	svc.registerHandlerForUtxoEvents()
	svc.registerHandlerForWalletEvents()

	return svc
}

func (ts *TransactionService) GetTransactionInfo(
	ctx context.Context, txid string,
) (*TransactionInfo, error) {
	tx, err := ts.repoManager.TransactionRepository().GetTransaction(ctx, txid)
	if err != nil {
		return nil, err
	}
	return (*TransactionInfo)(tx), nil
}

func (ts *TransactionService) SelectUtxos(
	ctx context.Context, accountName, targetAsset string, targetAmount uint64,
	coinSelectionStrategy int,
) (Utxos, uint64, int64, error) {
	account, err := ts.getAccount(ctx, accountName)
	if err != nil {
		return nil, 0, -1, err
	}

	utxos, err := ts.repoManager.UtxoRepository().GetSpendableUtxosForAccount(
		ctx, account.Namespace,
	)
	if err != nil {
		return nil, 0, -1, err
	}

	coinSelector := DefaultCoinSelector
	if factory, ok := coinSelectorByType[coinSelectionStrategy]; ok {
		coinSelector = factory()
	}

	utxos, change, err := coinSelector.SelectUtxos(utxos, targetAmount, targetAsset)
	if err != nil {
		return nil, 0, -1, err
	}
	now := time.Now()
	lockExpiration := now.Add(ts.utxoExpiryDuration)
	keys := Utxos(utxos).Keys()
	count, err := ts.repoManager.UtxoRepository().LockUtxos(
		ctx, keys, now.Unix(), lockExpiration.Unix(),
	)
	if err != nil {
		return nil, 0, -1, err
	}
	if count > 0 {
		ts.log(
			"locked %d utxo(s) for account %s (%s)",
			count, account.Namespace, UtxoKeys(keys),
		)
	}

	expirationDate := time.Now().Add(ts.utxoExpiryDuration).Unix()
	return utxos, change, expirationDate, nil
}

func (ts *TransactionService) EstimateFees(
	ctx context.Context, ins Inputs, outs Outputs, millisatsPerByte uint64,
) (uint64, error) {
	w, err := ts.repoManager.WalletRepository().GetWallet(ctx)
	if err != nil {
		return 0, err
	}

	lockedUtxosOnly := true
	walletInputs, err := ts.getWalletInputs(ctx, w, ins, !lockedUtxosOnly)
	if err != nil {
		return 0, err
	}
	externalInputs, err := ts.getExternalInputs(walletInputs, ins)
	if err != nil {
		return 0, err
	}

	if millisatsPerByte == 0 {
		millisatsPerByte = MinMillisatsPerByte
	}

	inputs := append(walletInputs, externalInputs...)
	return wallet.EstimateFees(
		inputs, outs.toWalletOutputs(), millisatsPerByte,
	), nil
}

func (ts *TransactionService) SignTransaction(
	ctx context.Context, txHex string, sighashType uint32,
) (string, error) {
	w, err := ts.repoManager.WalletRepository().GetWallet(ctx)
	if err != nil {
		return "", err
	}
	mnemonic, err := w.GetMnemonic()
	if err != nil {
		return "", err
	}

	ssInputs, msInputs, err := ts.findLockedInputs(ctx, w, txHex)
	if err != nil {
		return "", err
	}

	tx := txHex
	if len(ssInputs) > 0 {
		ww, _ := singlesig.NewWalletFromMnemonic(singlesig.NewWalletFromMnemonicArgs{
			RootPath: ts.rootPath,
			Mnemonic: mnemonic,
		})
		tx, err = ww.SignTransaction(singlesig.SignTransactionArgs{
			TxHex:        txHex,
			InputsToSign: ssInputs,
			SigHashType:  txscript.SigHashType(sighashType),
		})
		if err != nil {
			return "", err
		}
	}

	if len(msInputs) > 0 {
		for _, a := range msInputs {
			ww, _ := multisig.NewWalletFromMnemonic(multisig.NewWalletFromMnemonicArgs{
				RootPath: a.account.DerivationPath,
				Mnemonic: mnemonic,
				Xpubs:    a.account.Xpubs,
			})
			tx, err = ww.SignTransaction(multisig.SignTransactionArgs{
				TxHex:        tx,
				InputsToSign: a.inputs,
				SigHashType:  txscript.SigHashType(sighashType),
			})
			if err != nil {
				return "", err
			}
			tx, err = ts.cosigner.SignTx(ctx, tx, a.account.Id())
			if err != nil {
				return "", err
			}
		}
	}

	return tx, nil
}

func (ts *TransactionService) BroadcastTransaction(
	ctx context.Context, txHex string,
) (string, error) {
	keys := utxoKeysFromRawTx(txHex)
	utxos, err := ts.repoManager.UtxoRepository().GetUtxosByKey(ctx, keys)
	if err != nil {
		return "", err
	}
	if len(utxos) > 0 {
		for _, u := range utxos {
			if !u.IsLocked() {
				return "", fmt.Errorf(
					"cannot broadcast transaction containing unlocked utxos",
				)
			}
		}
	}

	return ts.bcScanner.BroadcastTransaction(txHex)
}

func (ts *TransactionService) CreatePset(
	ctx context.Context, inputs Inputs, outputs Outputs,
) (string, error) {
	w, err := ts.repoManager.WalletRepository().GetWallet(ctx)
	if err != nil {
		return "", err
	}

	lockedUtxosOnly := true
	walletInputs, err := ts.getWalletInputs(ctx, w, inputs, lockedUtxosOnly)
	if err != nil {
		return "", err
	}
	if len(walletInputs) == 0 {
		return "", fmt.Errorf("no utxos found with given keys")
	}

	return wallet.CreatePset(wallet.CreatePsetArgs{
		Inputs:  walletInputs,
		Outputs: outputs.toWalletOutputs(),
	})
}

func (ts *TransactionService) UpdatePset(
	ctx context.Context, ptx string, inputs Inputs, outputs Outputs,
) (string, error) {
	w, err := ts.repoManager.WalletRepository().GetWallet(ctx)
	if err != nil {
		return "", err
	}

	lockedInputsOnly := true
	walletInputs, err := ts.getWalletInputs(ctx, w, inputs, lockedInputsOnly)
	if err != nil {
		return "", err
	}
	if len(walletInputs) == 0 {
		return "", fmt.Errorf("no utxos found with given keys")
	}

	return wallet.UpdatePset(wallet.UpdatePsetArgs{
		PsetBase64: ptx,
		Inputs:     walletInputs,
		Outputs:    outputs.toWalletOutputs(),
	})
}

func (ts *TransactionService) BlindPset(
	ctx context.Context,
	ptx string, extraUnblindedInputs []UnblindedInput, lastBlinder bool,
) (string, error) {
	w, err := ts.repoManager.WalletRepository().GetWallet(ctx)
	if err != nil {
		return "", err
	}

	ssInputs, msInputs, err := ts.findLockedInputs(ctx, w, ptx)
	if err != nil {
		return "", err
	}

	walletInputs := make(map[uint32]wallet.Input)
	for i, in := range ssInputs {
		walletInputs[i] = in
	}
	for _, v := range msInputs {
		for i, in := range v.inputs {
			walletInputs[i] = in
		}
	}

	pset, _ := psetv2.NewPsetFromBase64(ptx)
	for i, in := range extraUnblindedInputs {
		psetIn := pset.Inputs[i]
		prevout := psetIn.GetUtxo()
		// Blinders are serialized as transaction ids.
		assetBlinder, _ := elementsutil.TxIDToBytes(in.AssetBlinder)
		valueBlinder, _ := elementsutil.TxIDToBytes(in.AmountBlinder)
		var valueCommitment, assetCommitment, nonce []byte
		if prevout.IsConfidential() {
			valueCommitment, assetCommitment, nonce =
				prevout.Value, prevout.Asset, prevout.Nonce
		}
		walletInputs[in.Index] = wallet.Input{
			TxID:            elementsutil.TxIDFromBytes(psetIn.PreviousTxid),
			TxIndex:         psetIn.PreviousTxIndex,
			Value:           in.Amount,
			Asset:           in.Asset,
			Script:          prevout.Script,
			ValueBlinder:    valueBlinder,
			AssetBlinder:    assetBlinder,
			ValueCommitment: valueCommitment,
			AssetCommitment: assetCommitment,
			Nonce:           nonce,
			RangeProof:      psetIn.UtxoRangeProof,
		}
	}

	return wallet.BlindPsetWithOwnedInputs(
		wallet.BlindPsetWithOwnedInputsArgs{
			PsetBase64:         ptx,
			OwnedInputsByIndex: walletInputs,
			LastBlinder:        lastBlinder,
		},
	)
}

func (ts *TransactionService) SignPset(
	ctx context.Context, ptx string, sighashType uint32,
) (string, error) {
	w, err := ts.repoManager.WalletRepository().GetWallet(ctx)
	if err != nil {
		return "", err
	}

	mnemonic, err := w.GetMnemonic()
	if err != nil {
		return "", err
	}

	ssInputs, msInputs, err := ts.findLockedInputs(ctx, w, ptx)
	if err != nil {
		return "", err
	}

	tx := ptx
	if len(ssInputs) > 0 {
		derivationPaths := make(map[string]string)
		for _, in := range ssInputs {
			script := hex.EncodeToString(in.Script)
			derivationPaths[script] = in.DerivationPath
		}

		ww, _ := singlesig.NewWalletFromMnemonic(singlesig.NewWalletFromMnemonicArgs{
			Mnemonic: mnemonic,
			RootPath: w.RootPath,
		})

		tx, err = ww.SignPset(singlesig.SignPsetArgs{
			PsetBase64:        ptx,
			DerivationPathMap: derivationPaths,
			SigHashType:       txscript.SigHashType(sighashType),
		})
		if err != nil {
			return "", err
		}
	}

	if len(msInputs) > 0 {
		for _, a := range msInputs {
			ww, _ := multisig.NewWalletFromMnemonic(multisig.NewWalletFromMnemonicArgs{
				RootPath: a.account.DerivationPath,
				Mnemonic: mnemonic,
				Xpubs:    a.account.Xpubs,
			})

			derivationPaths := make(map[string]string)
			for _, in := range a.inputs {
				script := hex.EncodeToString(in.Script)
				derivationPaths[script] = in.DerivationPath
			}

			tx, err = ww.SignPset(multisig.SignPsetArgs{
				PsetBase64:        tx,
				DerivationPathMap: derivationPaths,
				SigHashType:       txscript.SigHashType(sighashType),
			})
			if err != nil {
				return "", err
			}

			tx, err = ts.cosigner.SignTx(ctx, tx, a.account.Id())
			if err != nil {
				return "", err
			}
		}
	}

	return tx, nil
}

func (ts *TransactionService) Transfer(
	ctx context.Context, accountName string, outputs Outputs,
	millisatsPerByte uint64,
) (string, error) {
	w, err := ts.repoManager.WalletRepository().GetWallet(ctx)
	if err != nil {
		return "", err
	}
	mnemonic, err := w.GetMnemonic()
	if err != nil {
		return "", err
	}
	account, err := ts.getAccount(ctx, accountName)
	if err != nil {
		return "", err
	}

	utxoRepo := ts.repoManager.UtxoRepository()
	walletRepo := ts.repoManager.WalletRepository()

	balance, err := utxoRepo.GetBalanceForAccount(ctx, account.Namespace)
	if err != nil {
		return "", err
	}
	if len(balance) <= 0 {
		return "", fmt.Errorf("account %s has 0 balance", accountName)
	}

	utxos, err := utxoRepo.GetSpendableUtxosForAccount(
		ctx, account.Namespace,
	)
	if err != nil {
		return "", err
	}
	if len(utxos) == 0 {
		return "", fmt.Errorf("no utxos found for account %s", accountName)
	}

	changeByAsset := make(map[string]uint64)
	selectedUtxos := make([]*domain.Utxo, 0)
	lbtc := ts.network.AssetID
	for targetAsset, targetAmount := range outputs.totalAmountByAsset() {
		utxos, change, err := DefaultCoinSelector.SelectUtxos(utxos, targetAmount, targetAsset)
		if err != nil {
			return "", err
		}
		selectedUtxos = append(selectedUtxos, utxos...)
		if change > 0 {
			changeByAsset[targetAsset] = change
		}
	}

	inputs := make([]wallet.Input, 0, len(utxos))
	inputsByIndex := make(map[uint32]wallet.Input)
	for i, u := range selectedUtxos {
		input := wallet.Input{
			TxID:            u.TxID,
			TxIndex:         u.VOut,
			Value:           u.Value,
			Asset:           u.Asset,
			Script:          u.Script,
			ValueBlinder:    u.ValueBlinder,
			AssetBlinder:    u.AssetBlinder,
			ValueCommitment: u.ValueCommitment,
			AssetCommitment: u.AssetCommitment,
			Nonce:           u.Nonce,
			RangeProof:      u.RangeProof,
			SurjectionProof: u.SurjectionProof,
			RedeemScript:    u.RedeemScript,
		}
		inputs = append(inputs, input)
		inputsByIndex[uint32(i)] = input
	}

	changeOutputs := make([]wallet.Output, 0)
	if len(changeByAsset) > 0 {
		addressesInfo, err := walletRepo.DeriveNextInternalAddressesForAccount(
			ctx, account.Namespace, uint64(len(changeByAsset)),
		)
		if err != nil {
			return "", err
		}

		i := 0
		for asset, amount := range changeByAsset {
			script, _ := hex.DecodeString(addressesInfo[i].Script)
			addr, _ := address.FromConfidential(addressesInfo[i].Address)
			changeOutputs = append(changeOutputs, wallet.Output{
				Asset:       asset,
				Amount:      amount,
				Script:      script,
				BlindingKey: addr.BlindingKey,
			})
			i++
		}
	}

	outs := outputs.toWalletOutputs()
	feeAmount := wallet.EstimateFees(
		inputs, append(outs, changeOutputs...), millisatsPerByte,
	)

	// If feeAmount is lower than the lbtc change, it's enough to deduct it
	// from the change amount.
	if feeAmount < changeByAsset[lbtc] {
		for i, out := range changeOutputs {
			if out.Asset == lbtc {
				changeOutputs[i].Amount -= feeAmount
				break
			}
		}
	}
	// If feeAmount is exactly the lbtc change, it's enough to remove the
	// change output.
	if feeAmount == changeByAsset[lbtc] {
		var outIndex int
		for i, out := range changeOutputs {
			if out.Asset == lbtc {
				outIndex = i
				break
			}
		}
		changeOutputs = append(
			changeOutputs[:outIndex], changeOutputs[outIndex+1:]...,
		)
	}
	// If feeAmount is greater than the lbtc change, another coin-selection round
	// is required only in case the user is not trasferring the whole balance.
	// In that case the fee amount is deducted from the lbtc output with biggest.
	if feeAmount > changeByAsset[lbtc] {
		if changeByAsset[lbtc] == 0 {
			outIndex := 0
			for i, out := range outputs {
				if out.Asset == lbtc {
					if out.Amount > outputs[outIndex].Amount {
						outIndex = i
					}
				}
			}
			outs[outIndex] = wallet.Output{
				Asset:        outs[outIndex].Asset,
				Amount:       outs[outIndex].Amount - feeAmount,
				Script:       outs[outIndex].Script,
				BlindingKey:  outs[outIndex].BlindingKey,
				BlinderIndex: outs[outIndex].BlinderIndex,
			}
		} else {
			targetAsset := lbtc
			targetAmount := wallet.DummyFeeAmount
			if account.IsMultiSig() {
				targetAmount = wallet.DummyFeeAmount
			}
			if feeAmount > targetAmount {
				targetAmount = roundUpAmount(feeAmount)
			}

			// Coin-selection must be done over remaining utxos.
			remainingUtxos := getRemainingUtxos(utxos, selectedUtxos)
			selectedUtxos, change, err := DefaultCoinSelector.SelectUtxos(
				remainingUtxos, targetAmount, targetAsset,
			)
			if err != nil {
				return "", err
			}

			for _, u := range selectedUtxos {
				input := wallet.Input{
					TxID:            u.TxID,
					TxIndex:         u.VOut,
					Value:           u.Value,
					Asset:           u.Asset,
					Script:          u.Script,
					ValueBlinder:    u.ValueBlinder,
					AssetBlinder:    u.AssetBlinder,
					ValueCommitment: u.ValueCommitment,
					AssetCommitment: u.AssetCommitment,
					Nonce:           u.Nonce,
					RangeProof:      u.RangeProof,
					SurjectionProof: u.SurjectionProof,
					RedeemScript:    u.RedeemScript,
				}
				inputs = append(inputs, input)
				inputsByIndex[uint32(len(inputs))] = input
			}

			if change > 0 {
				// For the eventual change amount, it might be necessary to add a lbtc
				// change output to the list if it's still not in the list.
				if _, ok := changeByAsset[targetAsset]; !ok {
					addrInfo, err := walletRepo.DeriveNextInternalAddressesForAccount(
						ctx, account.Namespace, 1,
					)
					if err != nil {
						return "", err
					}
					script, _ := hex.DecodeString(addrInfo[0].Script)
					changeOutputs = append(changeOutputs, wallet.Output{
						Amount:      change,
						Asset:       targetAsset,
						Script:      script,
						BlindingKey: addrInfo[0].BlindingKey,
					})
				}

				// Now that we have all inputs and outputs, estimate the real fee amount.
				feeAmount = wallet.EstimateFees(
					inputs, append(outs, changeOutputs...), millisatsPerByte,
				)

				// Update the change amount by adding the delta
				// delta = targetAmount - feeAmount.
				for i, out := range changeOutputs {
					if out.Asset == targetAsset {
						// This way the delta is subtracted in case it's negative.
						changeOutputs[i].Amount = uint64(int(out.Amount) + int(targetAmount) - int(feeAmount))
						break
					}
				}
			}
		}
	}

	outs = append(outs, changeOutputs...)
	outs = append(outs, wallet.Output{
		Asset:  ts.network.AssetID,
		Amount: feeAmount,
	})

	ptx, err := wallet.CreatePset(wallet.CreatePsetArgs{
		Inputs:  inputs,
		Outputs: outs,
	})
	if err != nil {
		return "", err
	}

	blindedPtx, err := wallet.BlindPsetWithOwnedInputs(
		wallet.BlindPsetWithOwnedInputsArgs{
			PsetBase64:         ptx,
			OwnedInputsByIndex: inputsByIndex,
			LastBlinder:        true,
		},
	)
	if err != nil {
		return "", err
	}
	var signedPtx string
	if account.IsMultiSig() {
		ww, _ := multisig.NewWalletFromMnemonic(multisig.NewWalletFromMnemonicArgs{
			RootPath: account.DerivationPath,
			Mnemonic: mnemonic,
			Xpubs:    account.Xpubs,
		})
		signedPtx, err = ww.SignPset(multisig.SignPsetArgs{
			PsetBase64:        blindedPtx,
			DerivationPathMap: account.DerivationPathByScript,
		})
		if err != nil {
			return "", err
		}
		signedPtx, err = ts.cosigner.SignTx(ctx, signedPtx, account.Id())
		if err != nil {
			return "", err
		}
	} else {
		ww, _ := singlesig.NewWalletFromMnemonic(singlesig.NewWalletFromMnemonicArgs{
			RootPath: w.RootPath,
			Mnemonic: mnemonic,
		})
		signedPtx, err = ww.SignPset(singlesig.SignPsetArgs{
			PsetBase64:        blindedPtx,
			DerivationPathMap: account.DerivationPathByScript,
		})
		if err != nil {
			return "", err
		}
	}

	txHex, _, err := wallet.FinalizeAndExtractTransaction(wallet.FinalizeAndExtractTransactionArgs{
		PsetBase64: signedPtx,
	})
	if err != nil {
		return "", err
	}

	keys := Utxos(selectedUtxos).Keys()
	now := time.Now()
	lockExpiration := now.Add(ts.utxoExpiryDuration)
	count, err := ts.repoManager.UtxoRepository().LockUtxos(
		ctx, keys, now.Unix(), lockExpiration.Unix(),
	)
	if err != nil {
		return "", err
	}
	if count > 0 {
		ts.log(
			"locked %d utxo(s) for account %s (%s) ",
			count, account.Namespace, UtxoKeys(keys),
		)
	}

	return txHex, nil
}

func (ts *TransactionService) registerHandlerForWalletEvents() {
	ts.repoManager.RegisterHandlerForWalletEvent(
		domain.WalletUnlocked, func(_ domain.WalletEvent) {
			ts.scheduleUtxoUnlocker()
		},
	)
}

func (ts *TransactionService) registerHandlerForUtxoEvents() {
	ts.repoManager.RegisterHandlerForUtxoEvent(
		domain.UtxoLocked, func(event domain.UtxoEvent) {
			keys := UtxosInfo(event.Utxos).Keys()
			ts.spawnUtxoUnlocker(keys)
		},
	)
}

// scheduleUtxoUnlocker waits 5 seconds before whether unlocking or spawning an
// unlocker for all the locked utxos of each account.
// Since this method is called when the service is istantiated, the idea is to
// to give the account service enough time to receive notification from the
// blockchain scanner and spend the locked utxos.
func (ts *TransactionService) scheduleUtxoUnlocker() {
	time.Sleep(5 * time.Second)

	ctx := context.Background()
	utxoRepo := ts.repoManager.UtxoRepository()
	w, _ := ts.repoManager.WalletRepository().GetWallet(ctx)

	for accountName := range w.Accounts {
		utxos, _ := utxoRepo.GetLockedUtxosForAccount(
			ctx, accountName,
		)
		if len(utxos) > 0 {
			utxosToUnlock := make([]domain.UtxoKey, 0, len(utxos))
			utxosToSpawnUnlocker := make([]domain.UtxoKey, 0, len(utxos))
			for _, u := range utxos {
				if u.CanUnlock() {
					utxosToUnlock = append(utxosToUnlock, u.Key())
				} else {
					utxosToSpawnUnlocker = append(utxosToSpawnUnlocker, u.Key())
				}
			}

			if len(utxosToUnlock) > 0 {
				count, err := utxoRepo.UnlockUtxos(ctx, utxosToUnlock)
				if err != nil {
					utxosToSpawnUnlocker = append(utxosToSpawnUnlocker, utxosToUnlock...)
				}
				if count > 0 {
					ts.log(
						"unlocked %d utxo(s) for account %s (%s)",
						count, accountName, UtxoKeys(utxosToUnlock),
					)
				}
			}
			if len(utxosToSpawnUnlocker) > 0 {
				ts.spawnUtxoUnlocker(utxosToSpawnUnlocker)
			}
		}
	}
}

// spawnUtxoUnlocker groups the locked utxos identified by the given keys by their
// locking timestamps, and then creates a goroutine for each group in order to unlock
// the utxos if they are still locked when their expiration time comes.
func (ts *TransactionService) spawnUtxoUnlocker(utxoKeys []domain.UtxoKey) {
	ctx := context.Background()
	utxos, _ := ts.repoManager.UtxoRepository().GetUtxosByKey(ctx, utxoKeys)

	utxosByLockTimestamp := make(map[int64][]domain.UtxoKey)
	for _, u := range utxos {
		utxosByLockTimestamp[u.LockTimestamp] = append(
			utxosByLockTimestamp[u.LockTimestamp], u.Key(),
		)
	}

	for timestamp := range utxosByLockTimestamp {
		keys := utxosByLockTimestamp[timestamp]
		unlockTime := ts.utxoExpiryDuration - time.Since(time.Unix(timestamp, 0))
		t := time.NewTicker(unlockTime)
		quitChan := make(chan struct{})
		go func(keys []domain.UtxoKey, t *time.Ticker, quitChan chan struct{}) {
			ts.log("spawning unlocker for utxo(s) %s", UtxoKeys(keys))
			ts.log(fmt.Sprintf(
				"utxo(s) will be eventually unlocked in ~%.0f seconds",
				math.Round(unlockTime.Seconds()/10)*10,
			))

			for {
				select {
				case <-quitChan:
					return
				case <-t.C:
					utxos, _ := ts.repoManager.UtxoRepository().GetUtxosByKey(ctx, keys)
					utxosToUnlock := make([]domain.UtxoKey, 0, len(utxos))
					spentUtxos := make([]domain.UtxoKey, 0, len(utxos))
					for _, u := range utxos {
						if u.IsSpent() {
							spentUtxos = append(spentUtxos, u.Key())

						} else if u.IsLocked() {
							utxosToUnlock = append(utxosToUnlock, u.Key())
						}
					}

					if len(utxosToUnlock) > 0 {
						// In case of errors here, the ticker is possibly reset to a shortest
						// duration to keep retring to unlock the locked utxos as soon as
						// possible.
						count, err := ts.repoManager.UtxoRepository().UnlockUtxos(
							ctx, utxosToUnlock,
						)
						if err != nil {
							shortDuration := 5 * time.Second
							if shortDuration < unlockTime {
								t.Reset(shortDuration)
							}
							continue
						}

						if count > 0 {
							ts.log("unlocked %d utxo(s) %s", count, UtxoKeys(keys))
						}
						t.Stop()
					}
					if len(spentUtxos) > 0 {
						ts.log(
							"utxo(s) %s have been spent, skipping unlocking",
							UtxoKeys(spentUtxos),
						)
						t.Stop()
						quitChan <- struct{}{}
					}
				}
			}
		}(keys, t, quitChan)
	}
}

func (ts *TransactionService) getWalletMnemonic(
	ctx context.Context,
) ([]string, error) {
	w, err := ts.repoManager.WalletRepository().GetWallet(ctx)
	if err != nil {
		return nil, err
	}
	return w.GetMnemonic()
}

func (ts *TransactionService) getAccount(
	ctx context.Context, accountName string,
) (*domain.Account, error) {
	w, err := ts.repoManager.WalletRepository().GetWallet(ctx)
	if err != nil {
		return nil, err
	}
	return w.GetAccount(accountName)
}

func (ts *TransactionService) getWalletInputs(
	ctx context.Context, w *domain.Wallet, ins Inputs, wantsLocked bool,
) ([]wallet.Input, error) {
	keys := make([]domain.UtxoKey, 0, len(ins))
	for _, in := range ins {
		keys = append(keys, in.toUtxoKey())
	}
	utxos, err := ts.repoManager.UtxoRepository().GetUtxosByKey(ctx, keys)
	if err != nil {
		return nil, err
	}

	inputs := make([]wallet.Input, 0, len(utxos))
	for _, u := range utxos {
		if wantsLocked && !u.IsLocked() {
			return nil, ErrForbiddenUnlockedInputs
		}

		account, _ := w.GetAccount(u.AccountName)
		script := hex.EncodeToString(u.Script)
		derivationPath := account.DerivationPathByScript[script]

		inputs = append(inputs, wallet.Input{
			TxID:            u.TxID,
			TxIndex:         u.VOut,
			Value:           u.Value,
			Asset:           u.Asset,
			Script:          u.Script,
			ValueBlinder:    u.ValueBlinder,
			AssetBlinder:    u.AssetBlinder,
			ValueCommitment: u.ValueCommitment,
			AssetCommitment: u.AssetCommitment,
			Nonce:           u.Nonce,
			RangeProof:      u.RangeProof,
			SurjectionProof: u.SurjectionProof,
			DerivationPath:  derivationPath,
			RedeemScript:    u.RedeemScript,
		})
	}

	return inputs, nil
}

type accountInput struct {
	account *domain.Account
	inputs  map[uint32]wallet.Input
}

func (ts *TransactionService) findLockedInputs(
	ctx context.Context, w *domain.Wallet, tx string,
) (map[uint32]wallet.Input, map[string]accountInput, error) {
	rawTx, _ := transaction.NewTxFromHex(tx)
	var keys = make([]domain.UtxoKey, 0)
	if rawTx != nil {
		keys = utxoKeysFromRawTx(tx)
	} else {
		keys = utxoKeysFromPartialTx(tx)
	}

	utxos, err := ts.repoManager.UtxoRepository().GetUtxosByKey(ctx, keys)
	if err != nil {
		return nil, nil, err
	}
	if len(utxos) == 0 {
		return nil, nil, fmt.Errorf("no wallet utxos found in given transaction")
	}

	ssInputs := make(map[uint32]wallet.Input)
	msInputs := make(map[string]accountInput)
	for _, u := range utxos {
		if !u.IsLocked() {
			return nil, nil, fmt.Errorf(
				"cannot use unlocked utxos. The utxos used within 'external' " +
					"transactions must be coming from a coin selection so that they " +
					"can be locked to prevent double spending them",
			)

		}
		account, _ := w.GetAccount(u.AccountName)
		script := hex.EncodeToString(u.Script)
		inIndex := findUtxoIndexInTx(tx, u)
		in := wallet.Input{
			TxID:            u.TxID,
			TxIndex:         u.VOut,
			Value:           u.Value,
			Asset:           u.Asset,
			Script:          u.Script,
			ValueBlinder:    u.ValueBlinder,
			AssetBlinder:    u.AssetBlinder,
			ValueCommitment: u.ValueCommitment,
			AssetCommitment: u.AssetCommitment,
			Nonce:           u.Nonce,
			DerivationPath:  account.DerivationPathByScript[script],
		}
		if account.IsMultiSig() {
			accountName := account.Namespace
			if _, ok := msInputs[accountName]; !ok {
				msInputs[accountName] = accountInput{account, make(map[uint32]wallet.Input)}
			}
			msInputs[accountName].inputs[inIndex] = in
		} else {
			ssInputs[inIndex] = in
		}
	}
	return ssInputs, msInputs, nil
}

func (ts *TransactionService) getExternalInputs(
	walletIns []wallet.Input, txIns Inputs,
) ([]wallet.Input, error) {
	isExternalInput := func(in Input) bool {
		for _, walletIn := range walletIns {
			if walletIn.TxID == in.TxID && walletIn.TxIndex == in.VOut {
				return false
			}
		}
		return true
	}
	externalUtxos := make([]domain.Utxo, 0)
	for _, in := range txIns {
		if isExternalInput(in) {
			externalUtxos = append(externalUtxos, in.toUtxo())
		}
	}

	if len(externalUtxos) == 0 {
		return nil, nil
	}

	utxos, err := ts.bcScanner.GetUtxos(externalUtxos)
	if err != nil {
		return nil, err
	}

	externalInputs := make([]wallet.Input, 0, len(utxos))
	for _, u := range utxos {
		externalInputs = append(externalInputs, wallet.Input{
			TxID:            u.TxID,
			TxIndex:         u.VOut,
			Value:           u.Value,
			Asset:           u.Asset,
			ValueCommitment: u.ValueCommitment,
			AssetCommitment: u.AssetCommitment,
			Script:          u.Script,
		})
	}
	return externalInputs, nil
}

func utxoKeysFromRawTx(txHex string) []domain.UtxoKey {
	tx, _ := transaction.NewTxFromHex(txHex)
	keys := make([]domain.UtxoKey, 0, len(tx.Inputs))
	for _, in := range tx.Inputs {
		keys = append(keys, domain.UtxoKey{
			TxID: elementsutil.TxIDFromBytes(in.Hash),
			VOut: in.Index,
		})
	}
	return keys
}

func utxoKeysFromPartialTx(psetBase64 string) []domain.UtxoKey {
	tx, _ := psetv2.NewPsetFromBase64(psetBase64)
	keys := make([]domain.UtxoKey, 0, len(tx.Inputs))
	for _, in := range tx.Inputs {
		keys = append(keys, domain.UtxoKey{
			TxID: elementsutil.TxIDFromBytes(in.PreviousTxid),
			VOut: in.PreviousTxIndex,
		})
	}
	return keys
}

func findUtxoIndexInTx(tx string, utxo *domain.Utxo) uint32 {
	rawTx, _ := transaction.NewTxFromHex(tx)
	if rawTx != nil {
		return findUtxoIndexInRawTx(tx, utxo)
	}

	return findUtxoIndexInPartialTx(tx, utxo)
}

func findUtxoIndexInRawTx(txHex string, utxo *domain.Utxo) uint32 {
	tx, _ := transaction.NewTxFromHex(txHex)

	for i, in := range tx.Inputs {
		key := domain.UtxoKey{
			TxID: elementsutil.TxIDFromBytes(in.Hash),
			VOut: in.Index,
		}
		if utxo.Key() == key {
			return uint32(i)
		}
	}
	return uint32(len(tx.Inputs) - 1)
}

func findUtxoIndexInPartialTx(psetBase64 string, utxo *domain.Utxo) uint32 {
	tx, _ := psetv2.NewPsetFromBase64(psetBase64)

	for i, in := range tx.Inputs {
		key := domain.UtxoKey{
			TxID: elementsutil.TxIDFromBytes(in.PreviousTxid),
			VOut: in.PreviousTxIndex,
		}
		if utxo.Key() == key {
			return uint32(i)
		}
	}
	return uint32(len(tx.Inputs) - 1)
}

func roundUpAmount(amount uint64) uint64 {
	roundedAmount := float64(amount)
	orderOfMagnitude := 0
	for roundedAmount > 10 {
		roundedAmount /= 10
		orderOfMagnitude++
	}
	roundedAmount = math.Ceil(roundedAmount)
	roundedAmount *= math.Pow10(orderOfMagnitude)
	return uint64(roundedAmount)
}

func getRemainingUtxos(utxos, selectedUtxos []*domain.Utxo) []*domain.Utxo {
	remainingUtxos := make([]*domain.Utxo, 0)
	for _, u := range utxos {
		isSelected := false
		for _, su := range selectedUtxos {
			if u.Key() == su.Key() {
				isSelected = true
				break
			}
		}
		if isSelected {
			continue
		}
		remainingUtxos = append(remainingUtxos, u)
	}
	return remainingUtxos
}

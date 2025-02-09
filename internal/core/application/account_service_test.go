package application_test

import (
	"encoding/hex"
	"testing"

	"github.com/equitas-foundation/bamp-ocean/internal/core/application"
	"github.com/equitas-foundation/bamp-ocean/internal/core/domain"
	"github.com/equitas-foundation/bamp-ocean/internal/core/ports"
	dbbadger "github.com/equitas-foundation/bamp-ocean/internal/infrastructure/storage/db/badger"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAccountService(t *testing.T) {
	domain.MnemonicStore = newInMemoryMnemonicStore()
	mockedBcScanner := newMockedBcScanner()
	mockedBcScanner.On("GetLatestBlock").Return(birthdayBlockHash, birthdayBlockHeight, nil)
	mockedCosigner := newMockedCosigner()
	mockedCosigner.On("GetXpub", mock.Anything).Return(cosignerXpub, nil)
	repoManager, err := newRepoManagerForAccountService()
	require.NoError(t, err)
	require.NotNil(t, repoManager)

	svc := application.NewAccountService(repoManager, mockedBcScanner, mockedCosigner)

	addresses, err := svc.DeriveAddressesForAccount(ctx, accountName, 0)
	require.Error(t, err)
	require.Nil(t, addresses)

	accountInfo, err := svc.CreateAccountBIP44(ctx, accountName)
	require.NoError(t, err)
	require.NotNil(t, accountInfo)
	require.Equal(t, accountName, accountInfo.Label)
	require.Equal(t, accountNamespace, accountInfo.Namespace)
	require.NotEmpty(t, accountInfo.DerivationPath)
	require.NotEmpty(t, accountInfo.Xpubs)

	addresses, err = svc.ListAddressesForAccount(ctx, accountName)
	require.NoError(t, err)
	require.Empty(t, addresses)

	addresses, err = svc.DeriveAddressesForAccount(ctx, accountName, 2)
	require.NoError(t, err)
	require.Len(t, addresses, 2)

	changeAddresses, err := svc.DeriveChangeAddressesForAccount(ctx, accountName, 0)
	require.NoError(t, err)
	require.Len(t, changeAddresses, 1)

	addresses, err = svc.ListAddressesForAccount(ctx, accountName)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(addresses), 2)

	utxos, err := svc.ListUtxosForAccount(ctx, accountName)
	require.NoError(t, err)
	require.NotNil(t, utxos)
	require.NotEmpty(t, utxos.Spendable)
	require.Empty(t, utxos.Locked)

	balance, err := svc.GetBalanceForAccount(ctx, accountName)
	require.NoError(t, err)
	require.NotNil(t, balance)

	// Cannot delete an account with non-zero balance.
	err = svc.DeleteAccount(ctx, accountName)
	require.Error(t, err)

	// Simulate withdrawing all funds by spending every spendable utxo coming
	// from ListUtxosForAccount.
	status := domain.UtxoStatus{hex.EncodeToString(make([]byte, 32)), 1, 0, ""}
	_, err = repoManager.UtxoRepository().SpendUtxos(ctx, utxos.Spendable.Keys(), status)
	require.NoError(t, err)

	// Now deleting the account should work without errors.
	err = svc.DeleteAccount(ctx, accountName)
	require.NoError(t, err)
}

func newRepoManagerForAccountService() (ports.RepoManager, error) {
	rm, err := dbbadger.NewRepoManager("", nil)
	if err != nil {
		return nil, err
	}

	wallet, err := domain.NewWallet(
		mnemonic, password, rootPath, msRootPath, regtest.Name,
		birthdayBlockHeight, nil, nil,
	)
	if err != nil {
		return nil, err
	}

	if err := rm.WalletRepository().CreateWallet(ctx, wallet); err != nil {
		return nil, err
	}

	if err := rm.WalletRepository().UpdateWallet(
		ctx, func(w *domain.Wallet) (*domain.Wallet, error) {
			w.Unlock(password)
			return w, nil
		},
	); err != nil {
		return nil, err
	}

	return rm, nil
}

package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	path "github.com/equitas-foundation/bamp-ocean/pkg/wallet/derivation-path"
	multisig "github.com/equitas-foundation/bamp-ocean/pkg/wallet/multi-sig"
	singlesig "github.com/equitas-foundation/bamp-ocean/pkg/wallet/single-sig"
)

// AccountInfo holds basic info about an account.
type AccountInfo struct {
	Namespace      string
	Label          string
	Xpubs          []string
	DerivationPath string
}

func (a AccountInfo) Descriptor() string {
	return fmt.Sprintf("elwsh(sortedmulti(%d, %s))", len(a.Xpubs), strings.Join(a.Xpubs, ","))
}

func (i *AccountInfo) GetMasterBlindingKey() (string, error) {
	mnemonic := MnemonicStore.Get()
	if len(i.Xpubs) > 1 {
		ww, _ := multisig.NewWalletFromMnemonic(multisig.NewWalletFromMnemonicArgs{
			RootPath: i.DerivationPath,
			Mnemonic: mnemonic,
			Xpubs:    i.Xpubs,
		})
		return ww.MasterBlindingKey()
	}

	rootPath, _ := path.ParseDerivationPath(i.DerivationPath)
	rootPath = rootPath[:len(rootPath)-1]
	ww, _ := singlesig.NewWalletFromMnemonic(singlesig.NewWalletFromMnemonicArgs{
		RootPath: rootPath.String(),
		Mnemonic: mnemonic,
	})
	return ww.MasterBlindingKey()
}

// Account defines the entity data struture for a derived account of the
// daemon's HD wallet
type Account struct {
	AccountInfo
	Index                  uint32
	BirthdayBlock          uint32
	NextExternalIndex      uint
	NextInternalIndex      uint
	DerivationPathByScript map[string]string
}

func (a *Account) IsMultiSig() bool {
	return len(a.AccountInfo.Xpubs) > 1
}

func (a *Account) Id() string {
	id := sha256.Sum256([]byte(a.AccountInfo.Descriptor()))
	return hex.EncodeToString(id[:])
}

func (a *Account) incrementExternalIndex() (next uint) {
	// restart from 0 if index has reached the its max value
	next = 0
	if a.NextExternalIndex != hdkeychain.HardenedKeyStart-1 {
		next = a.NextExternalIndex + 1
	}
	a.NextExternalIndex = next
	return
}

func (a *Account) incrementInternalIndex() (next uint) {
	next = 0
	if a.NextInternalIndex != hdkeychain.HardenedKeyStart-1 {
		next = a.NextInternalIndex + 1
	}
	a.NextInternalIndex = next
	return
}

func (a *Account) addDerivationPath(outputScript, derivationPath string) {
	if _, ok := a.DerivationPathByScript[outputScript]; !ok {
		a.DerivationPathByScript[outputScript] = derivationPath
	}
}

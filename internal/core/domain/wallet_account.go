package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

// AccountKey holds the unique info of an account: name and HD index.
type AccountKey struct {
	Name  string
	Index uint32
}

func (ak *AccountKey) String() string {
	key := btcutil.Hash160([]byte(fmt.Sprintf("%s%d", ak.Name, ak.Index)))
	return hex.EncodeToString(key[:6])
}

// AccountInfo holds basic info about an account.
type AccountInfo struct {
	Key            AccountKey
	Xpubs          []string
	DerivationPath string
}

func (a AccountInfo) Descriptor() string {
	return fmt.Sprintf("elwsh(sortedmulti(%d, %s))", len(a.Xpubs), strings.Join(a.Xpubs, ","))
}

// Account defines the entity data struture for a derived account of the
// daemon's HD wallet
type Account struct {
	Info                   AccountInfo
	BirthdayBlock          uint32
	NextExternalIndex      uint
	NextInternalIndex      uint
	DerivationPathByScript map[string]string
}

func (a *Account) IsMultiSig() bool {
	return len(a.Info.Xpubs) > 1
}

func (a *Account) Id() string {
	id := sha256.Sum256([]byte(a.Info.Descriptor()))
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

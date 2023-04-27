package electrum_scanner

import (
	"github.com/equitas-foundation/bamp-ocean/internal/core/domain"
	"github.com/vulpemventures/go-elements/transaction"
)

type electrumClient interface {
	listen()
	close()

	subscribeForBlocks()
	subscribeForAccount(
		account string, addresses []domain.AddressInfo,
	) (chan accountReport, map[string][]txInfo)
	unsubscribeForAccount(account string)

	getLatestBlock() ([]byte, uint32, error)
	getBlocksInfo(heights []uint32) ([]blockInfo, error)
	getScriptHashesHistory(scriptHashes []string) (map[string][]txInfo, error)
	getTxs(txids []string) ([]*transaction.Transaction, error)
	getUtxos(outpoints []domain.Utxo) ([]domain.Utxo, error)
	broadcastTx(txHex string) (string, error)
}

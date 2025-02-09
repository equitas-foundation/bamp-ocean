package postgresdb

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jackc/pgx/v4/pgxpool"

	"github.com/equitas-foundation/bamp-ocean/internal/core/domain"
	"github.com/equitas-foundation/bamp-ocean/internal/core/ports"
	"github.com/equitas-foundation/bamp-ocean/internal/infrastructure/storage/db/postgres/sqlc/queries"

	_ "github.com/golang-migrate/migrate/v4/source/file"
)

const (
	postgresDriver             = "pgx"
	insecureDataSourceTemplate = "postgresql://%s:%s@%s:%d/%s?sslmode=disable"
)

type repoManager struct {
	pgxPool *pgxpool.Pool

	utxoRepository   *utxoRepositoryPg
	walletRepository *walletRepositoryPg
	txRepository     *txRepositoryPg

	walletEventHandlers *handlerMap
	utxoEventHandlers   *handlerMap
	txEventHandlers     *handlerMap
}

func NewRepoManager(dbConfig DbConfig) (ports.RepoManager, error) {
	dataSource := insecureDataSourceStr(dbConfig)

	pgxPool, err := connect(dataSource)
	if err != nil {
		return nil, err
	}

	if err = migrateDb(dataSource, dbConfig.MigrationSourceURL); err != nil {
		return nil, err
	}

	utxoRepository := newUtxoRepositoryPgImpl(pgxPool)
	walletRepository := newWalletRepositoryPgImpl(pgxPool)
	txRepository := newTxRepositoryPgImpl(pgxPool)

	rm := &repoManager{
		pgxPool:             pgxPool,
		utxoRepository:      utxoRepository,
		walletRepository:    walletRepository,
		txRepository:        txRepository,
		walletEventHandlers: newHandlerMap(),
		utxoEventHandlers:   newHandlerMap(),
		txEventHandlers:     newHandlerMap(),
	}

	go rm.listenToWalletEvents()
	go rm.listenToUtxoEvents()
	go rm.listenToTxEvents()

	return rm, nil
}

type DbConfig struct {
	DbUser             string
	DbPassword         string
	DbHost             string
	DbPort             int
	DbName             string
	MigrationSourceURL string
}

func (rm *repoManager) UtxoRepository() domain.UtxoRepository {
	return rm.utxoRepository
}

func (rm *repoManager) WalletRepository() domain.WalletRepository {
	return rm.walletRepository
}

func (rm *repoManager) TransactionRepository() domain.TransactionRepository {
	return rm.txRepository
}

func (rm *repoManager) RegisterHandlerForWalletEvent(
	eventType domain.WalletEventType, handler ports.WalletEventHandler,
) {
	rm.walletEventHandlers.set(int(eventType), handler)
}

func (rm *repoManager) RegisterHandlerForUtxoEvent(
	eventType domain.UtxoEventType, handler ports.UtxoEventHandler,
) {
	rm.utxoEventHandlers.set(int(eventType), handler)
}

func (rm *repoManager) RegisterHandlerForTxEvent(
	eventType domain.TransactionEventType, handler ports.TxEventHandler,
) {
	rm.txEventHandlers.set(int(eventType), handler)
}

func (rm *repoManager) listenToWalletEvents() {
	for event := range rm.walletRepository.chEvents {
		time.Sleep(time.Millisecond)

		if handlers, ok := rm.walletEventHandlers.get(int(event.EventType)); ok {
			for i := range handlers {
				handler := handlers[i]
				go handler.(ports.WalletEventHandler)(event)
			}
		}
	}
}

func (rm *repoManager) listenToUtxoEvents() {
	for event := range rm.utxoRepository.chEvents {
		time.Sleep(time.Millisecond)

		if handlers, ok := rm.utxoEventHandlers.get(int(event.EventType)); ok {
			for i := range handlers {
				handler := handlers[i]
				go handler.(ports.UtxoEventHandler)(event)
			}
		}
	}
}

func (rm *repoManager) listenToTxEvents() {
	for event := range rm.txRepository.chEvents {
		time.Sleep(time.Millisecond)

		if handlers, ok := rm.txEventHandlers.get(int(event.EventType)); ok {
			for i := range handlers {
				handler := handlers[i]
				go handler.(ports.TxEventHandler)(event)
			}
		}
	}
}

func (rm *repoManager) Reset() {
	ctx := context.Background()
	conn, err := rm.pgxPool.Acquire(ctx)
	if err != nil {
		return
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)

	querier := new(queries.Queries)
	querier = querier.WithTx(tx)
	rm.walletRepository.reset(querier, ctx)
	rm.utxoRepository.reset(querier, ctx)
	rm.txRepository.reset(querier, ctx)

	tx.Commit(ctx)
}

func (rm *repoManager) Close() {
	rm.utxoRepository.close()
	rm.txRepository.close()
	rm.walletRepository.close()

	rm.pgxPool.Close()
}

// handlerMap is a util type to prevent race conditions when registering
// or retrieving handlers for events.
type handlerMap struct {
	handlersByEventType map[int][]interface{}
	lock                *sync.RWMutex
}

func newHandlerMap() *handlerMap {
	return &handlerMap{
		handlersByEventType: make(map[int][]interface{}),
		lock:                &sync.RWMutex{},
	}
}

func (m *handlerMap) set(key int, val interface{}) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.handlersByEventType[key] = append(m.handlersByEventType[key], val)
}

func (m *handlerMap) get(key int) ([]interface{}, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	val, ok := m.handlersByEventType[key]
	return val, ok
}

func connect(dataSource string) (*pgxpool.Pool, error) {
	return pgxpool.Connect(context.Background(), dataSource)
}

func migrateDb(dataSource, migrationSourceUrl string) error {
	pg := postgres.Postgres{}

	d, err := pg.Open(dataSource)
	if err != nil {
		return err
	}

	m, err := migrate.NewWithDatabaseInstance(
		migrationSourceUrl,
		postgresDriver,
		d,
	)
	if err != nil {
		return err
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}

	return nil
}

// insecureDataSourceStr converts database configuration params to connection string
func insecureDataSourceStr(dbConfig DbConfig) string {
	return fmt.Sprintf(
		insecureDataSourceTemplate,
		dbConfig.DbUser,
		dbConfig.DbPassword,
		dbConfig.DbHost,
		dbConfig.DbPort,
		dbConfig.DbName,
	)
}

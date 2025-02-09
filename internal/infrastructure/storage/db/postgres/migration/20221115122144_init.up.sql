CREATE TABLE wallet (
    id varchar(255) NOT NULL PRIMARY KEY,
    encrypted_mnemonic bytea NOT NULL,
    password_hash bytea NOT NULL,
    birthday_block_height INTEGER NOT NULL,
    root_path VARCHAR(64) NOT NULL,
    ms_root_path VARCHAR(64) NOT NULL,
    network_name VARCHAR(64) NOT NULL,
    next_account_index INTEGER NOT NULL,
    next_ms_account_index INTEGER NOT NULL
);

CREATE TABLE account (
    namespace VARCHAR(50) NOT NULL PRIMARY KEY,
    index INTEGER NOT NULL,
    label VARCHAR(500),
    xpubs VARCHAR(200) ARRAY NOT NULL,
    derivation_path VARCHAR(200) NOT NULL,
    next_external_index INTEGER NOT NULL,
    next_internal_index INTEGER NOT NULL,
    fk_wallet_id VARCHAR(255) NOT NULL,
    FOREIGN KEY (fk_wallet_id) REFERENCES wallet(id) ON DELETE CASCADE
);

CREATE TABLE account_script_info (
    script VARCHAR(1000) NOT NULL PRIMARY KEY,
    derivation_path VARCHAR(200) NOT NULL,
    fk_account_name VARCHAR(50) NOT NULL,
    FOREIGN KEY (fk_account_name) REFERENCES account(namespace) ON DELETE CASCADE
);

CREATE TABLE transaction (
    tx_id VARCHAR(64) NOT NULL PRIMARY KEY,
    tx_hex VARCHAR(10485760) NOT NULL,
    block_hash VARCHAR(64) NOT NULL,
    block_height INTEGER NOT NULL
);

CREATE TABLE tx_input_account (
    id SERIAL PRIMARY KEY,
    account_name VARCHAR(50) NOT NULL,
    fk_tx_id VARCHAR(64) NOT NULL,
    FOREIGN KEY (fk_tx_id) REFERENCES transaction(tx_id) ON DELETE CASCADE
);

CREATE TABLE utxo (
    id SERIAL PRIMARY KEY,
    tx_id VARCHAR(64) NOT NULL,
    vout INTEGER NOT NULL,
    value BIGINT NOT NULL,
    asset VARCHAR(64) NOT NULL,
    value_commitment bytea,
    asset_commitment bytea,
    value_blinder bytea NOT NULL,
    asset_blinder bytea NOT NULL,
    script bytea NOT NULL,
    redeem_script bytea,
    nonce bytea,
    range_proof bytea,
    surjection_proof bytea,
    account_name varchar(50) NOT NULL,
    lock_timestamp BIGINT NOT NULL,
    lock_expiry_timestamp BIGINT NOT NULL,
    UNIQUE (tx_id, vout)
);

CREATE TABLE utxo_status (
    id SERIAL PRIMARY KEY,
    block_height INTEGER NOT NULL,
    block_time BIGINT NOT NULL,
    block_hash varchar(64) NOT NULL,
    status integer NOT NULL,
    fk_utxo_id integer NOT NULL,
    FOREIGN KEY (fk_utxo_id) REFERENCES utxo(id) ON DELETE CASCADE
);
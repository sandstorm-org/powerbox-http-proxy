package main

import (
	"context"
	"database/sql"
)

type Storage struct {
	db *sql.DB
}

func NewStorage(db *sql.DB) (Storage, error) {
	s := Storage{db: db}
	return s, s.Init()
}

func (s Storage) Init() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS powerbox_proxy_tokens (
		url TEXT NOT NULL,
		token TEXT NOT NULL
	)`)
	return err
}

func (s Storage) GetTokenFor(url string) (token string, err error) {
	return s.GetTokenForContext(context.Background(), url)
}

func (s Storage) GetTokenForContext(ctx context.Context, url string) (token string, err error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT token
		FROM powerbox_proxy_tokens
		WHERE url = ?`,
		url,
	)
	err = row.Scan(&token)
	return token, err
}

func (s Storage) SetTokenFor(url, token string) error {
	return s.SetTokenForContext(context.Background(), url, token)
}

func (s Storage) SetTokenForContext(ctx context.Context, url, token string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // Will no-op if we've already comitted.
	_, err = tx.ExecContext(ctx,
		`DELETE FROM powerbox_proxy_tokens
		WHERE url = ?`,
		url,
	)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO powerbox_proxy_tokens(url, token)
		VALUES (?, ?)`,
		url, token,
	)
	if err == nil {
		err = tx.Commit()
	}
	return err
}

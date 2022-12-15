package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/cockroachdb/cockroach-go/v2/crdb/crdbpgx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

var (
	accountList         sync.Map
	port                string = "8000"
	suspiciousTransfers        = 0
	transfers                  = 0
)

const (
	minAmount = 0
	maxAmount = 1000
	reason    = "Suspicious activity detected!"
)

type (
	fraudDetector struct {
		pool *pgxpool.Pool
	}
	Message struct {
		Destination string   `json:"destination"`
		Key         []string `json:"key"`
		Source      string   `json:"source"`
	}
)

func (fd fraudDetector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		return
	}
	newLine := []byte{'\n'}
	ms := bytes.Split(buf, newLine)
	for _, v := range ms {
		var m Message
		err := json.Unmarshal(v, &m)
		if err != nil {
			log.Println("JSON parse error", err.Error())
			return
		}
		go checkForFraud(fd.pool, m.Source, m.Destination)
	}
}

func checkForFraud(pool *pgxpool.Pool, source, destination string) {
	err := crdbpgx.ExecuteTx(context.Background(), pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		return isFraud(context.Background(), tx, source, destination)
	})

	if err != nil {
		log.Println(err)
	}
}

func isFraud(ctx context.Context, tx pgx.Tx, source, destination string) error {
	var n sql.NullInt64
	err := tx.QueryRow(ctx, "SELECT isFraud($1, $2)", source, destination).Scan(&n)

	if err != nil {
		if err.Error() != "no rows in result set" {
			return nil
		}
		return err
	}

	//too much transfers done!!!
	if n.Int64 > 0 {
		if _, err := tx.Exec(ctx, "INSERT INTO anomalies (source, destination, reason) VALUES ($1, $2, $3)", source, destination, reason); err != nil {
			log.Println(err)
		}
		log.Println(reason)
	}

	return nil
}

func main() {
	duration := flag.Int("d", 1*3600, "number of seconds to run (default 3600)")
	wait := flag.Int("w", 250, "wait between order in ms (default 250)")
	accountsPtr := flag.Int("a", 100, "number of accounts to create (default 100)")
	flag.Parse()
	if *accountsPtr <= 1 {
		*accountsPtr = 2
	}

	// Read in connection string
	var config *pgxpool.Config
	var err error
	config, err = pgxpool.ParseConfig(os.Getenv("DB"))
	if err != nil {
		log.Fatal(err)
	}
	dbpool, err := pgxpool.ConnectConfig(context.Background(), config)
	if err != nil {
		log.Fatal(err)
	}
	defer dbpool.Close()

	clean(dbpool)
	createAccounts(dbpool, accountsPtr)
	go run(dbpool, accountsPtr, duration, wait)

	err = http.ListenAndServe(fmt.Sprintf(":%v", port), fraudDetector{pool: dbpool})
	if err != nil {
		panic(err)
	}
}

func createAccounts(pool *pgxpool.Pool, accounts *int) {
	// Insert initial rows
	log.Printf("creating %d accounts...", *accounts)
	var wg sync.WaitGroup
	wg.Add(*accounts)

	for i := 0; i < *accounts; i++ {
		go func(pool *pgxpool.Pool, index int) {
			defer wg.Done()
			id := uuid.New()
			err := crdbpgx.ExecuteTx(context.Background(), pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
				return insertRows(context.Background(), tx, id, randomize(10, 1*1000*1000))
			})
			if err == nil {
				accountList.Store(index, id)
			} else {
				log.Fatal("error: ", err)
			}
		}(pool, i)
	}
	wg.Wait()

	log.Println("accounts created")
}

func clean(pool *pgxpool.Pool) {
	err := crdbpgx.ExecuteTx(context.Background(), pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		return prepTables(context.Background(), tx)
	})
	if err != nil {
		log.Fatal(err)
	}
}

func prepTables(ctx context.Context, tx pgx.Tx) error {
	log.Println("cleansing table...")
	if _, err := tx.Exec(ctx, "TRUNCATE TABLE accounts"); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "TRUNCATE TABLE transfers"); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "TRUNCATE TABLE anomalies"); err != nil {
		return err
	}
	log.Println("tables cleansed")

	return nil
}

func insertRows(ctx context.Context, tx pgx.Tx, acct uuid.UUID, balance int) error {
	if _, err := tx.Exec(ctx,
		"INSERT INTO accounts (id, balance) VALUES ($1, $2)", acct, balance); err != nil {
		return err
	}
	return nil
}

func run(pool *pgxpool.Pool, accounts, duration, wait *int) {
	// Run transfers
	log.Printf("starting transfers for %d s", *duration)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*duration)*time.Second)
	go callTransfer(ctx, pool, accounts, wait)

	//Cancel if too long
	ct := time.Duration(*duration)
	select {
	case <-ctx.Done():
		cancel()
		return
	case <-time.After(ct * time.Second):
		log.Println("finished")
		cancel()
	}
}

func callTransfer(ctx context.Context, pool *pgxpool.Pool, accounts, wait *int) {
	w := time.Duration(*wait) * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			log.Printf("done %d transfers (%d suspicious transfers detected)", transfers, suspiciousTransfers)
			return
		default:
			srcid := randomize(0, *accounts)
			src, ok := accountList.Load(srcid)
			if !ok {
				log.Println("source account not found ", srcid)
				return
			}
			dstid := randomize(0, *accounts)
			dst, ok := accountList.Load(dstid)
			if !ok {
				log.Println("destination account not found ", dstid)
				return
			}
			amount := randomize(minAmount, maxAmount)
			err := crdbpgx.ExecuteTx(context.Background(), pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
				return transferFunds(context.Background(), tx, src.(uuid.UUID), dst.(uuid.UUID), amount)
			})
			if err != nil {
				log.Println("error: ", err)
			} else {
				log.Printf("transfer from %s to %s of %d done.\n", src.(uuid.UUID), dst.(uuid.UUID), amount)
			}
			log.Printf("Waiting %d ms.", *wait)
			time.Sleep(w)
		}
	}
}

func transferFunds(ctx context.Context, tx pgx.Tx, from uuid.UUID, to uuid.UUID, amount int) error {
	//Check for authorization
	var isAuthorized sql.NullString
	err := tx.QueryRow(ctx, "SELECT reason FROM anomalies WHERE source = $1 AND destination = $2", from, to).Scan(&isAuthorized)

	if err != nil && err.Error() != "no rows in result set" {
		return err
	}

	if isAuthorized.String != "" {
		suspiciousTransfers++
		tx.Rollback(ctx)
		return errors.New(isAuthorized.String)
	}

	// Read the balance.
	var fromBalance int
	if err := tx.QueryRow(ctx,
		"SELECT balance FROM accounts WHERE id = $1", from).Scan(&fromBalance); err != nil {
		return err
	}

	if fromBalance < amount {
		tx.Rollback(ctx)
		return errors.New("insufficent funds")
	}
	// Perform the transfer.
	if _, err := tx.Exec(ctx,
		"UPDATE accounts SET balance = balance - $1 WHERE id = $2", amount, from); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		"UPDATE accounts SET balance = balance + $1 WHERE id = $2", amount, to); err != nil {
		return err
	}
	tid := uuid.New()
	if _, err := tx.Exec(ctx,
		"INSERT INTO transfers (id, source, destination, amount) VALUES ($1, $2, $3, $4)", tid, from, to, amount); err != nil {
		return err
	}
	transfers++
	return nil
}

func randomize(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return min + rand.Intn(max-min)
}

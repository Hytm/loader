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
	minAmount      = 0
	maxAmount      = 1000
	reason         = "Suspicious activity detected!"
	notAnomaly     = "Ok"
	warning        = "Warning"
	alert          = "Alert"
	blockThreshold = 20
)

type (
	fraudDetector struct {
		pool *pgxpool.Pool
	}
	Message struct {
		Id          string   `json:"id"`
		Key         []string `json:"key"`
		Source      string   `json:"source"`
		Destination string   `json:"destination"`
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
		go blockAccount(fd.pool, m)
	}
}

func blockAccount(pool *pgxpool.Pool, m Message) {
	//Check anomaly level
	err := crdbpgx.ExecuteTx(context.Background(), pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		return isAnomaly(context.Background(), tx, m)
	})

	if err != nil {
		log.Println(err)
	}

	//Block account based on anomaly
	err = crdbpgx.ExecuteTx(context.Background(), pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		return needToBlockAccount(context.Background(), tx, m.Source)
	})

	if err != nil {
		log.Println(err)
	}
}

func isAnomaly(ctx context.Context, tx pgx.Tx, m Message) error {
	var anomaly string
	err := tx.QueryRow(ctx, "SELECT anomalyLevel($1)", m.Id).Scan(&anomaly)

	if err != nil {
		if err.Error() != "no rows in result set" {
			return nil
		}
		return err
	}

	//Add anomaly to table
	if anomaly != notAnomaly {
		if _, err := tx.Exec(ctx, "INSERT INTO anomalies (source, destination, level) VALUES ($1, $2, $3)", m.Source, m.Destination, anomaly); err != nil {
			log.Println(err)
		}
		log.Println(reason)
	}

	return nil
}

func needToBlockAccount(ctx context.Context, tx pgx.Tx, source string) error {
	rows, err := tx.Query(ctx, "SELECT anomaly_level, count(*) FROM transfers WHERE source = '$1' GROUP BY anomaly_level", source)
	if err != nil {
		if err.Error() != "no rows in result set" {
			return nil
		}
		return err
	}

	rate := 0
	for rows.Next() {
		level := ""
		count := 0
		err := rows.Scan(&level, &count)
		if err != nil {
			return err
		}
		switch level {
		case warning:
			rate += count
		case alert:
			rate += 5 * count
		}
	}

	//Add account to blocked accounts
	if rate >= blockThreshold {
		if _, err := tx.Exec(ctx, "INSERT INTO blocked_accounts (source, reason) VALUES ($1, $2)", source, reason); err != nil {
			log.Println(err)
			return err
		}
	}

	return nil
}

func main() {
	duration := flag.Int("d", 1*3600, "number of seconds to run (default 3600)")
	wait := flag.Int("w", 1000, "wait between order in ms (default 1000)")
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
	err := tx.QueryRow(ctx, "SELECT reason FROM blocked_accounts WHERE source = $1", from).Scan(&isAuthorized)

	if err != nil && err.Error() != "no rows in result set" {
		return err
	}

	if isAuthorized.String != "" {
		suspiciousTransfers++
		return errors.New(isAuthorized.String)
	}

	// Read the balance.
	var fromBalance int
	if err := tx.QueryRow(ctx,
		"SELECT balance FROM accounts WHERE id = $1", from).Scan(&fromBalance); err != nil {
		return err
	}

	if fromBalance < amount {
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

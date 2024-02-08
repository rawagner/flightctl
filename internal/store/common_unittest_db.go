package store

import (
	"fmt"
	"strings"

	"github.com/flightctl/flightctl/internal/config"
	"github.com/google/uuid"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func PrepareDBForUnitTests(log *logrus.Logger) (*gorm.DB, *Store, *config.Config, string) {
	cfg := config.NewDefault()
	cfg.Database.Name = ""
	dbTemp, err := InitDB(cfg)
	Expect(err).ShouldNot(HaveOccurred())
	defer CloseDB(dbTemp)

	randomDBName := fmt.Sprintf("_%s", strings.ReplaceAll(uuid.New().String(), "-", "_"))
	log.Infof("DB name: %s", randomDBName)
	dbTemp = dbTemp.Exec(fmt.Sprintf("CREATE DATABASE %s;", randomDBName))
	Expect(dbTemp.Error).ShouldNot(HaveOccurred())

	cfg.Database.Name = randomDBName
	db, err := InitDB(cfg)
	if err != nil {
		log.Fatalf("initializing data store: %v", err)
	}

	store := NewStore(db, log.WithField("pkg", "store"))
	if err := store.InitialMigration(); err != nil {
		log.Fatalf("running initial migration: %v", err)
	}

	err = store.InitialMigration()
	Expect(err).ShouldNot(HaveOccurred())

	return db, store, cfg, randomDBName
}

func DeleteTestDB(cfg *config.Config, db *gorm.DB, dbName string) {
	CloseDB(db)
	cfg.Database.Name = ""
	db, err := InitDB(cfg)
	Expect(err).ShouldNot(HaveOccurred())
	defer CloseDB(db)
	db = db.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s;", dbName))

	Expect(db.Error).ShouldNot(HaveOccurred())
}

func CloseDB(db *gorm.DB) {
	sqlDB, err := db.DB()
	if err != nil {
		return
	}
	_ = sqlDB.Close()
}
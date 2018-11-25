package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/boltdb/bolt"
	ostatus "github.com/emersion/go-ostatus"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"

	httph "github.com/Luzifer/go_helpers/http"

	"github.com/Luzifer/rconfig"
)

var (
	cfg = struct {
		AvatarURL        string        `flag:"avatar-url" default:"https://www.clker.com/cliparts/n/K/7/e/Q/M/rss-feed-md.png" description:"Image to use as avatar"`
		BaseURL          string        `flag:"base-url" default:"http://localhost:3000" description:"Base URL of this instance"`
		DatabasePath     string        `flag:"database-path" default:"./storage.db" description:"Path to store the database in"`
		FeedDefinitions  string        `flag:"feed-definitions" default:"./feeds.yml" description:"File with shortname to url associations"`
		FeedPollInterval time.Duration `flag:"feed-poll-interval,i" default:"1m" description:"How often to poll feeds for new entries"`
		Listen           string        `flag:"listen" default:":3000" description:"Port/IP to listen on"`
		LogLevel         string        `flag:"log-level" default:"info" description:"Log level (debug, info, warn, error, fatal)"`
		VersionAndExit   bool          `flag:"version" default:"false" description:"Prints current version and exits"`
	}{}

	version = "dev"
)

func init() {
	rconfig.AutoEnv(true)
	if err := rconfig.ParseAndValidate(&cfg); err != nil {
		log.Fatalf("Unable to parse commandline options: %s", err)
	}

	if cfg.VersionAndExit {
		fmt.Printf("rss-status %s\n", version)
		os.Exit(0)
	}

	if l, err := log.ParseLevel(cfg.LogLevel); err != nil {
		log.WithError(err).Fatal("Unable to parse log level")
	} else {
		log.SetLevel(l)
	}
}

func loadFeedDefinitions() (map[string]feedInfo, error) {
	f, err := os.Open(cfg.FeedDefinitions)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to open feed definition file")
	}
	defer f.Close()

	r := make(map[string]feedInfo)
	return r, errors.Wrap(yaml.NewDecoder(f).Decode(&r), "Unable to parse feed definition file")
}

func main() {
	db, err := bolt.Open(cfg.DatabasePath, 0600, nil)
	if err != nil {
		log.WithError(err).Fatal("Unable to open the database")
	}
	defer db.Close()

	fd, err := loadFeedDefinitions()
	if err != nil {
		log.WithError(err).Fatal("Unable to load feed definitions")
	}
	feeds := newFeedDB(fd)

	// Register oStatus implementation
	be, err := newBackend(db, cfg.BaseURL, feeds)
	if err != nil {
		log.WithError(err).Fatal("Unable to create backend")
	}

	h := ostatus.NewHandler(be, be.getHostMeta())
	http.Handle("/", httph.NewHTTPLogHandler(h))

	if err := newSubscriptionDB(h.Publisher, db); err != nil {
		log.WithError(err).Fatal("Unable to restore subscription db")
	}

	log.WithField("version", version).Info("rss-status operative")

	log.WithError(http.ListenAndServe(cfg.Listen, nil)).Fatal("HTTP-Server quit unexpectedly")
}

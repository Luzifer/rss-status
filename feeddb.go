package main

import (
	"sort"
	"sync"
	"time"

	"github.com/SlyMarbo/rss"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type feedInfo struct {
	DisplayName string `yaml:"display_name"`
	ProfileURL  string `yaml:"profile_url"`
	FeedURL     string `yaml:"feed_url"`
}

type feedDBEntry struct {
	Items       []*rss.Item
	LastUpdated time.Time
	Info        feedInfo
}

type feedDB struct {
	feeds map[string]feedDBEntry

	lock sync.RWMutex
}

func newFeedDB(feedConfig map[string]feedInfo) *feedDB {
	f := &feedDB{
		feeds: make(map[string]feedDBEntry),
	}

	for feedName, info := range feedConfig {
		f.feeds[feedName] = feedDBEntry{
			Info: info,
		}

		// Initialize database at startup
		if _, err := f.Update(feedName); err != nil {
			log.WithField("feed_name", feedName).WithError(err).Error("Unable to refresh feed")
		}
	}

	return f
}

func (f *feedDB) entriesByFeedName(name string) []*rss.Item {
	f.lock.RLock()
	defer f.lock.RUnlock()

	if e, ok := f.feeds[name]; ok {
		return e.Items
	}

	return nil
}

func (f *feedDB) infoByFeedName(name string) *feedInfo {
	f.lock.RLock()
	defer f.lock.RUnlock()

	if e, ok := f.feeds[name]; ok {
		return &e.Info
	}

	return nil
}

func (f *feedDB) Update(feedName string) (bool, error) {
	f.lock.RLock()
	fe := f.feeds[feedName]
	f.lock.RUnlock()

	if len(fe.Items) > 0 && fe.LastUpdated.Add(cfg.FeedPollInterval).After(time.Now()) {
		// Don't poll more often than requested
		return false, nil
	}

	feed, err := rss.Fetch(fe.Info.FeedURL)
	if err != nil {
		return false, errors.Wrap(err, "Unable to retrieve feed")
	}

	// Reverse sort (newest to oldest): swapped i, j
	sort.Slice(feed.Items, func(j, i int) bool { return feed.Items[i].Date.Before(feed.Items[j].Date) })

	fe.Items = feed.Items
	fe.LastUpdated = time.Now()

	f.lock.Lock()
	f.feeds[feedName] = fe
	f.lock.Unlock()

	return true, nil
}

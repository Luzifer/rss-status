package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 - As this is only obfuscation this is acceptable
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/SlyMarbo/rss"
	"github.com/boltdb/bolt"
	ostatus "github.com/emersion/go-ostatus"
	"github.com/emersion/go-ostatus/activitystream"
	"github.com/emersion/go-ostatus/pubsubhubbub"
	"github.com/emersion/go-ostatus/salmon"
	"github.com/emersion/go-ostatus/xrd"
	"github.com/emersion/go-ostatus/xrd/lrdd"
	"github.com/emersion/go-ostatus/xrd/webfinger"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const keyBits = 2048

var (
	keysBucket = []byte("RSAKeys")
	dateBucket = []byte("FeedLastUpdate")
)

type subscription struct {
	ticker   *time.Ticker
	notifies chan<- pubsubhubbub.Event
}

type backend struct {
	salmon.PublicKeyBackend

	baseURL string
	db      *bolt.DB
	domain  string
	feeds   *feedDB
	topics  map[string]*subscription
}

func newBackend(db *bolt.DB, baseURL string, feeds *feedDB) (*backend, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to parse base-URL")
	}

	return &backend{
		PublicKeyBackend: salmon.NewPublicKeyBackend(),

		baseURL: baseURL,
		db:      db,
		domain:  u.Host,
		feeds:   feeds,
		topics:  make(map[string]*subscription),
	}, nil
}

func (b *backend) Feed(topicURL string) (*activitystream.Feed, error) {
	feedName := b.uriToFeedName(topicURL)
	if feedName == "" {
		log.WithField("topic", topicURL).Warn("Tried to fetch invalid topic")
		return nil, errors.New("Invalid topic")
	}

	items := b.feeds.entriesByFeedName(feedName)
	if items == nil {
		log.WithField("feed_name", feedName).Warn("Tried to fetch unknown feed")
		return nil, errors.New("Unknown feed")
	}

	feed, err := b.rssItemsToFeed(feedName, items)
	if err != nil {
		log.WithField("feed_name", feedName).WithError(err).Error("Unable to generate feed")
	}

	return feed, err
}

func (b backend) getHostMeta() *xrd.Resource {
	return &xrd.Resource{
		Links: []*xrd.Link{
			{Rel: lrdd.Rel, Type: "application/jrd+json", Template: b.baseURL + webfinger.WellKnownPathTemplate},
		},
	}
}

func (b backend) getFeedEnvelope(feedName string) *activitystream.Feed {
	feedURL := fmt.Sprintf("%s/@%s.atom", b.baseURL, feedName)
	acctURL := fmt.Sprintf("acct:%s@%s", feedName, b.domain)

	var lastUpdate = time.Now()
	if items := b.feeds.entriesByFeedName(feedName); len(items) > 0 {
		lastUpdate = items[0].Date
	}

	return &activitystream.Feed{
		ID:       feedURL,
		Title:    feedName,
		Logo:     cfg.AvatarURL,
		Subtitle: fmt.Sprintf("rss-status feed fetcher for %q feed", feedName),
		Updated:  activitystream.NewTime(lastUpdate),
		Link: []activitystream.Link{
			{Rel: "alternate", Type: "text/html", Href: feedURL},
			{Rel: "self", Type: "application/atom+xml", Href: feedURL},
			{Rel: pubsubhubbub.RelHub, Href: b.baseURL + ostatus.HubPath},
			{Rel: salmon.Rel, Href: b.baseURL + ostatus.SalmonPath},
		},
		Author: &activitystream.Person{
			ID:         acctURL,
			URI:        acctURL,
			Name:       feedName,
			Email:      fmt.Sprintf("%s@%s", feedName, b.domain),
			Summary:    fmt.Sprintf("rss-status feed fetcher for %q feed", feedName),
			ObjectType: activitystream.ObjectPerson,
			Link: []activitystream.Link{
				{Rel: "alternate", Type: "text/html", Href: fmt.Sprintf("%s/@%s.atom", b.baseURL, feedName)},
				{Rel: "avatar", Href: cfg.AvatarURL},
			},
			PreferredUsername: feedName,
			DisplayName:       feedName,
			Note:              fmt.Sprintf("rss-status feed fetcher for %q feed", feedName),
		},
	}
}

func (b backend) getFeedKey(feedName string) (crypto.PublicKey, error) {
	var pub crypto.PublicKey
	err := b.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(keysBucket)
		if err != nil {
			return err
		}

		k := []byte(feedName)
		v := b.Get(k)
		var priv *rsa.PrivateKey
		if v == nil {
			priv, err = rsa.GenerateKey(rand.Reader, keyBits)
			if err != nil {
				return err
			}

			v = x509.MarshalPKCS1PrivateKey(priv)
			if err = b.Put(k, v); err != nil {
				return err
			}
		} else {
			priv, err = x509.ParsePKCS1PrivateKey(v)
			if err != nil {
				return err
			}
		}

		pub = priv.Public()
		return nil
	})

	return pub, err
}

func (b backend) getFeedLastUpdate(feedName string) (time.Time, error) {
	t := time.Now() // Fallback: Assume last update was now

	err := b.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(dateBucket)
		if err != nil {
			return err
		}

		k := []byte(feedName)
		v := b.Get(k)

		if v != nil {
			t, err = time.Parse(time.RFC3339Nano, string(v))
		}

		return err
	})

	return t, err
}

func (b *backend) Notify(entry *activitystream.Entry) error {
	log.WithFields(log.Fields{
		"object_type": entry.ObjectType,
		"verb":        entry.Verb,
	}).Debug("Received event notification")

	if entry.ObjectType != activitystream.ObjectActivity {
		return errors.New("Unsupported object type")
	}

	switch entry.Verb {
	case activitystream.VerbFollow, activitystream.VerbUnfollow:
		return nil // Nothing to do
	default:
		return errors.New("Unsupported verb")
	}
}

// obfuscateFeedEntryID is to create url-safe obfuscations of the real feed
// IDs while maintaining low-propability for collisions
func (b *backend) obfuscateFeedEntryID(id string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(id))) // #nosec G401 - As this is only obfuscation this is acceptable
}

func (b *backend) Resource(uri string, rel []string) (*xrd.Resource, error) {
	feedName := b.uriToFeedName(uri)
	if feedName == "" {
		log.WithField("topic", uri).Warn("Tried to fetch invalid topic")
		return nil, errors.New("Invalid topic")
	}

	pub, err := b.getFeedKey(feedName)
	if err != nil {
		log.WithField("feed_name", feedName).WithError(err).Error("Unable to get / generate public key")
		return nil, errors.Wrap(err, "Unable to get / generate public key")
	}

	publicKeyURL, err := salmon.FormatPublicKeyDataURL(pub)
	if err != nil {
		log.WithField("feed_name", feedName).WithError(err).Error("Unable to create public key data URL")
		return nil, errors.Wrap(err, "Unable to create public key data URL")
	}

	accountURI := fmt.Sprintf("acct:%s@%s", feedName, b.domain)
	resource := &xrd.Resource{
		Subject: accountURI,
		Links: []*xrd.Link{
			{Rel: webfinger.RelProfilePage, Type: "text/html", Href: fmt.Sprintf("%s/@%s.atom", b.baseURL, feedName)},
			{Rel: pubsubhubbub.RelUpdatesFrom, Type: "application/atom+xml", Href: fmt.Sprintf("%s/@%s.atom", b.baseURL, feedName)},
			{Rel: salmon.Rel, Href: b.baseURL + ostatus.SalmonPath},
			{Rel: salmon.RelMagicPublicKey, Href: publicKeyURL},
		},
	}
	return resource, nil
}

func (b backend) rssItemsToFeed(feedName string, items []*rss.Item) (*activitystream.Feed, error) {
	feed := b.getFeedEnvelope(feedName)

	tpl, err := template.New("feedFormat").Parse(`<p>{{ if .Link }}<a href="{{ .Link }}">{{ .Title }}</a>{{ else }}{{ .Title }}{{ end }}</p>{{ .Summary }}`)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to parse entry template")
	}

	for _, i := range items {
		content := new(bytes.Buffer)
		if err := tpl.Execute(content, i); err != nil {
			return nil, errors.Wrap(err, "Unable to execute template")
		}

		entry := &activitystream.Entry{
			ID:         fmt.Sprintf("%s/status/%s/%x", b.baseURL, feedName, b.obfuscateFeedEntryID(i.ID)),
			Title:      "Post",
			ObjectType: activitystream.ObjectNote,
			Verb:       activitystream.VerbPost,
			Published:  activitystream.NewTime(i.Date),
			Updated:    activitystream.NewTime(i.Date),
			Link: []activitystream.Link{
				{Rel: "self", Type: "application/atom+xml", Href: fmt.Sprintf("%s/status/%s/%x.atom", b.baseURL, feedName, b.obfuscateFeedEntryID(i.ID))},
				{Rel: "alternate", Type: "text/html", Href: i.Link},
				{Rel: "mentioned", ObjectType: activitystream.ObjectCollection, Href: activitystream.CollectionPublic},
			},
			Content: &activitystream.Text{
				Type: "html",
				Lang: "en",
				Body: content.String(),
			},
		}

		feed.Entry = append(feed.Entry, entry)
	}

	return feed, nil
}

func (b backend) setFeedLastUpdate(feedName string, lastUpdate time.Time) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(dateBucket)
		if err != nil {
			return err
		}

		k := []byte(feedName)
		v := []byte(lastUpdate.Format(time.RFC3339Nano))
		return b.Put(k, v)
	})
}

func (b *backend) Subscribe(topicURL string, notifies chan<- pubsubhubbub.Event) error {
	feedName := b.uriToFeedName(topicURL)
	if feedName == "" {
		log.WithField("topic", topicURL).Warn("Tried to subscribe invalid topic")
		return errors.New("Invalid topic")
	}

	lastPostDate, err := b.getFeedLastUpdate(feedName)
	if err != nil {
		log.WithError(err).WithField("feed_name", feedName).Error("Unable to parse db stored last update")
		return errors.Wrap(err, "Unable to parse db stored last update")
	}

	ticker := time.NewTicker(cfg.FeedPollInterval)
	b.topics[topicURL] = &subscription{ticker, notifies}

	go func() {
		defer close(notifies)

		for range ticker.C {
			updated, err := b.feeds.Update(feedName)
			if err != nil {
				log.WithError(err).WithField("feed_name", feedName).Error("Unable to refresh feed")
				continue
			}

			// If the feed database refused the refresh do not send updates
			if !updated {
				continue
			}

			items := []*rss.Item{}
			maxDate := lastPostDate

			for _, i := range b.feeds.entriesByFeedName(feedName) {
				if i.Date.After(lastPostDate) {
					items = append(items, i)
					if i.Date.After(maxDate) {
						maxDate = i.Date
					}
				}
			}

			feed, err := b.rssItemsToFeed(feedName, items)
			if err != nil {
				log.WithError(err).WithField("feed_name", feedName).Error("Unable to build feed")
				continue
			}

			lastPostDate = maxDate
			notifies <- feed

			log.WithField("feed_name", feedName).Debug("Sent notification for feed update")

			if err = b.setFeedLastUpdate(feedName, lastPostDate); err != nil {
				log.WithError(err).WithField("feed_name", feedName).Error("Unable to store last update")
			}
		}
	}()

	return nil
}

func (b *backend) Unsubscribe(notifies chan<- pubsubhubbub.Event) error {
	for topic, sub := range b.topics {
		if notifies == sub.notifies {
			delete(b.topics, topic)
			sub.ticker.Stop()
			return nil
		}
	}

	return nil
}

func (b backend) uriToFeedName(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return ""
	}

	switch u.Scheme {
	case "acct":
		return strings.SplitN(u.Opaque, "@", 2)[0]
	case "http", "https", "":
		return strings.TrimSuffix(strings.Trim(u.Path, "/@"), ".atom")
	}
	return ""
}

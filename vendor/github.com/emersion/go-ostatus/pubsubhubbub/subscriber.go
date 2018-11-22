package pubsubhubbub

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"log"
)

// An HTTPError is an HTTP error. Its value is the HTTP status code.
type HTTPError int

// Error implements error.
func (err HTTPError) Error() string {
	return "pubsubhubbub: HTTP request failed"
}

// A DeniedError is returned when a publisher forbids subscription to a feed.
// Its value is the reason.
type DeniedError string

// Error implements error.
func (err DeniedError) Error() string {
	return "pubsubhubbub: subscription denied: " + string(err)
}

type subscription struct {
	callbackURL  string
	lease        time.Time
	secret       string
	notifies     chan<- Event
	subscribes   chan error
	unsubscribes chan error
}

// A Subscriber subscribes to publishers.
type Subscriber struct {
	c             *http.Client
	callbackURL   string
	subscriptions map[string]*subscription
	readEvent     ReadEventFunc
}

// NewSubscriber creates a new subscriber.
func NewSubscriber(callbackURL string, readEvent ReadEventFunc) *Subscriber {
	return &Subscriber{
		c:             new(http.Client),
		callbackURL:   callbackURL,
		subscriptions: make(map[string]*subscription),
		readEvent:     readEvent,
	}
}

func (s *Subscriber) request(hub string, data url.Values) error {
	resp, err := s.c.PostForm(hub, data)
	if err != nil {
		return err
	}
	resp.Body.Close() // We don't need the response body

	if resp.StatusCode != http.StatusAccepted {
		return HTTPError(resp.StatusCode)
	}

	return nil
}

// Subscribe subscribes to a topic on a hub. Notifications are sent to notifies.
func (s *Subscriber) Subscribe(hub, topic string, notifies chan<- Event) error {
	if _, ok := s.subscriptions[topic]; ok {
		return errors.New("pubsubhubbub: already subscribed")
	}

	secret, err := generateChallenge()
	if err != nil {
		return err
	}

	u, err := url.Parse(s.callbackURL)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("topic", topic)
	u.RawQuery = q.Encode()
	callbackURL := u.String()

	sub := &subscription{
		callbackURL:  callbackURL,
		notifies:     notifies,
		secret:       secret,
		subscribes:   make(chan error, 1),
		unsubscribes: make(chan error, 1),
	}
	s.subscriptions[topic] = sub

	data := make(url.Values)
	data.Set("hub.callback", callbackURL)
	data.Set("hub.mode", "subscribe")
	data.Set("hub.topic", topic)
	data.Set("hub.secret", secret)
	// hub.lease_seconds
	if err := s.request(hub, data); err != nil {
		return err
	}

	return <-sub.subscribes
}

// Unsubscribe unsubscribes from a topic on a hub.
func (s *Subscriber) Unsubscribe(hub, topic string) error {
	sub, ok := s.subscriptions[topic]
	if !ok {
		return errors.New("pubsubhubbub: no such subsciption")
	}

	data := make(url.Values)
	data.Set("hub.callback", sub.callbackURL)
	data.Set("hub.mode", "unsubscribe")
	data.Set("hub.topic", topic)
	if err := s.request(hub, data); err != nil {
		return err
	}

	return <-sub.unsubscribes
}

// ServeHTTP implements http.Handler.
func (s *Subscriber) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	query := req.URL.Query()
	switch req.Method {
	case http.MethodGet:
		mode := query.Get("hub.mode")
		topic := query.Get("hub.topic")

		sub, ok := s.subscriptions[topic]
		if !ok {
			http.Error(resp, "Not Found", http.StatusNotFound)
			return
		}

		switch mode {
		case "denied":
			reason := query.Get("hub.reason")
			log.Printf("pubsubhubbub: publisher denied request for topic %q (reason: %v)\n", topic, reason)
			delete(s.subscriptions, topic)
			close(sub.notifies)
			sub.subscribes <- DeniedError(reason)
			close(sub.subscribes)
			return
		case "subscribe":
			log.Printf("pubsubhubbub: publisher accepted subscription for topic %q\n", topic)
			lease, err := strconv.Atoi(query.Get("hub.lease_seconds"))
			if err != nil {
				http.Error(resp, "Bad Request", http.StatusBadRequest)
				return
			}
			sub.lease = time.Now().Add(time.Duration(lease) * time.Second)
			close(sub.subscribes)
		case "unsubscribe":
			log.Printf("pubsubhubbub: publisher accepted unsubscription for topic %q\n", topic)
			delete(s.subscriptions, topic)
			close(sub.notifies)
			close(sub.unsubscribes)
		default:
			http.Error(resp, "Bad Request", http.StatusBadRequest)
			return
		}

		resp.Write([]byte(query.Get("hub.challenge")))
	case http.MethodPost:
		topic := query.Get("topic")

		sub, ok := s.subscriptions[topic]
		if !ok {
			http.Error(resp, "Invalid topic", http.StatusNotFound)
			return
		}

		var r io.Reader = req.Body
		var h hash.Hash
		if sub.secret != "" {
			h = hmac.New(sha1.New, []byte(sub.secret))
			r = io.TeeReader(r, h)
		}

		event, err := s.readEvent(req.Header.Get("Content-Type"), r)
		if err != nil {
			http.Error(resp, "Invalid request body", http.StatusBadRequest)
			return
		}

		if event.Topic() != topic {
			http.Error(resp, "Invalid topic", http.StatusNotFound)
			return
		}

		// Make sure the whole body has been read
		io.Copy(ioutil.Discard, r)

		// Check signature
		if h != nil {
			s := strings.TrimPrefix(req.Header.Get("X-Hub-Signature"), "sha1=")
			mac, err := hex.DecodeString(s)
			if err != nil || !hmac.Equal(mac, h.Sum(nil)) {
				// Invalid signature
				// Ignore message, do not return an error
				log.Printf("pubsubhubbub: invalid signature for topic %q\n", topic)
				return
			}
		}

		sub.notifies <- event
	default:
		http.Error(resp, "Unsupported method", http.StatusMethodNotAllowed)
	}
}

package ostatus

import (
	"net/http"

	"github.com/emersion/go-ostatus/pubsubhubbub"
	"github.com/emersion/go-ostatus/salmon"
	"github.com/emersion/go-ostatus/xrd"
	"github.com/emersion/go-ostatus/xrd/hostmeta"
	"github.com/emersion/go-ostatus/xrd/webfinger"
)

// Default endpoints.
var (
	HubPath    = "/hub"
	SalmonPath = "/salmon"
)

// Handler handles OStatus requests.
type Handler struct {
	http.Handler

	Publisher *pubsubhubbub.Publisher
}

// NewHandler creates a new OStatus endpoint.
func NewHandler(be Backend, hostmetaResource *xrd.Resource) *Handler {
	mux := http.NewServeMux()
	h := &Handler{Handler: mux}

	p := pubsubhubbub.NewPublisher(be)
	h.Publisher = p

	mux.Handle(hostmeta.WellKnownPath, hostmeta.NewHandler(hostmetaResource))
	mux.Handle(webfinger.WellKnownPath, webfinger.NewHandler(be))
	mux.Handle(HubPath, p)
	mux.Handle(SalmonPath, salmon.NewHandler(be))

	mux.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request) {
		topic := req.URL.String()
		feed, err := be.Feed(topic)
		if err != nil {
			http.Error(resp, err.Error(), http.StatusInternalServerError)
			return
		}

		resp.Header().Set("Content-Type", "application/atom+xml")

		if feed.ID == "" && len(feed.Entry) == 1 {
			err = feed.Entry[0].WriteTo(resp)
		} else {
			err = feed.WriteTo(resp)
		}
		if err != nil {
			http.Error(resp, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	return h
}

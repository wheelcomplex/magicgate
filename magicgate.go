//

package magicgate

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

// HostStat record stat of a backend host
type HostStat struct {
}

// BackendList for reverse proxy
// <*|*.example.com|example.com>@10.0.0.2:9080:tls/be1.example.com:9080^iphash,
// target@backendlist^load‑balancing methods,[more target section],
// tls mark in backend list means connect to backend by tls
type BackendList struct {
	target     []byte           // the URI.HOST which client accessing, etc example.com or *.example.com or ip or 0.0.0.0, * means all
	hosts      [][]byte         // the backend host/ip list
	policy     []byte           // load‑balancing methods, roundrobin, IP hash, URI partent hash, random
	aliveHosts map[int]HostStat // hosts index as key
}

// NewBackendList return an initialed *backendList
func NewBackendList() *BackendList {
	return &BackendList{
		target:     make([]byte, 0),
		hosts:      make([][]byte, 0),
		policy:     make([]byte, 0),
		aliveHosts: make(map[int]HostStat),
	}
}

// NewBackendListFromArgs parse input args and return *backendList
func NewBackendListFromArgs(backendArgs string) *BackendList {
	be := NewBackendList()
	be.AddBackendArgs(backendArgs)
	return be
}

// AddBackendArgs add more backend to backendList
func (be *BackendList) AddBackendArgs(backendArgs string) error {

	return nil
}

// Todo: server ctrl, sync gate certs (storage dir) to authenticated client, for reverse proxy by tls

// ServerImp redirect HTTP requests to HTTPS
type ServerImp struct {
	LastURI string
	Counter int64

	CtrlToken []byte

	NormalHostSwitch   map[string]fasthttp.RequestHandler
	WildcardHostSwitch map[string]fasthttp.RequestHandler

	Domains           []string
	WildcardDomains   []string
	DefaultServerName string
	TrimList          [][]byte
	Backends          *BackendList
	// Todo: add command line flags

	mux sync.Mutex
}

// MatchHostHandler do handler matching on access host,
// will return nil for mismatch.
func (h *ServerImp) MatchHostHandler(name string) fasthttp.RequestHandler {

	if len(h.NormalHostSwitch) == 0 && len(h.WildcardHostSwitch) == 0 {
		log.Printf("MatchHostHandler, handler switch is empty for %s\n", name)
		return nil
	}

	// normal/single host
	if handler := h.NormalHostSwitch[name]; handler != nil {
		log.Printf("MatchHostHandler, match normal host: %s\n", name)
		return handler
	}

	// wildcard ip
	if handler := h.NormalHostSwitch["0.0.0.0"]; handler != nil && IsAllDotNumber(name) {
		log.Printf("MatchHostHandler, match wildcard ip host: %s\n", name)
		return handler
	}

	for oneDomain, handler := range h.WildcardHostSwitch {
		if strings.HasSuffix(name, oneDomain) {
			log.Printf("MatchHostHandler, match WILDCARD host (*%s): %s\n", oneDomain, name)
			return handler
		}
	}
	log.Printf("MatchHostHandler, host mismatch: %s\n", name)
	return nil
}

// Todo: test ServerHostSwitchHandler

// ServerHostSwitchHandler return a fasthttp.RequestHandler which select handler by request host
func (h *ServerImp) ServerHostSwitchHandler(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		log.Printf("ServerHostSwitchHandler(%s <= %s), requested path is %q(%q). LastURI is %q. Counter is %d", ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String(), h.LastURI, h.Counter)

		h.mux.Lock()
		h.LastURI = string(ctx.Path())
		h.Counter++
		h.mux.Unlock()

		reqHost := ctx.Host()

		var aclhost string
		var err error
		aclhost, _, err = net.SplitHostPort(string(reqHost))

		if err != nil {
			// not port come with request host
			aclhost = string(reqHost)
		}
		if handler := h.MatchHostHandler(string(aclhost)); handler != nil {
			log.Printf("ServerHostSwitchHandler, (%s <= %s), host switching for host: %s\n", ctx.LocalAddr(), ctx.RemoteAddr(), aclhost)
			handler(ctx)
			return
		}
		if next != nil {
			next(ctx)
		}
		return
	}
}

// DomainACL do ACL on access host
func (h *ServerImp) DomainACL(name string) error {

	if len(h.Domains) == 0 && len(h.WildcardDomains) == 0 {
		log.Printf("DomainACL, allow any domains: %s\n", name)
		return nil
	}

	// Todo: more effection way to check for massive domains
	// Todo: use map[host]bool to storage single host list
	for _, oneDomain := range h.Domains {
		if name == oneDomain {
			log.Printf("DomainACL, match normal domain: %s\n", name)
			return nil
		}

		// log.Printf("DomainACL, MISMATCH normal domain (%s): %s\n", oneDomain, name)
	}

	isIP := IsAllDotNumber(name)

	for _, oneDomain := range h.WildcardDomains {
		if strings.HasSuffix(name, oneDomain) {
			log.Printf("DomainACL, match WILDCARD domain (*%s): %s\n", oneDomain, name)
			return nil
		}
		if isIP && oneDomain == "0.0.0.0" {
			log.Printf("DomainACL, match WILDCARD IP: %s\n", name)
			return nil
		}
		// log.Printf("DomainACL, MISMATCH WILDCARD domain (*%s): %s\n", oneDomain, name)
	}
	log.Printf("DomainACL, not allowed domain: %s\n", name)
	return fmt.Errorf("not allowed domain %s", name)
}

// DomainACLNoIP do ACL on access host, IP not allowed
func (h *ServerImp) DomainACLNoIP(name string) error {

	if IsAllDotNumber(name) {
		log.Printf("DomainACLNoIP, not allowed IP %s", name)
		return fmt.Errorf("not allowed IP %s", name)
	}
	return h.DomainACL(name)
}

// ServerHandler return a fasthttp.RequestHandler which redirect a http request to https
func (h *ServerImp) ServerHandler(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		log.Printf("ServerHandler(%s <= %s), requested path is %q(%q). LastURI is %q. Counter is %d", ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String(), h.LastURI, h.Counter)

		h.mux.Lock()
		h.LastURI = string(ctx.Path())
		h.Counter++
		h.mux.Unlock()

		reqHost := ctx.Host()

		var aclhost string
		var err error
		aclhost, _, err = net.SplitHostPort(string(reqHost))

		if err != nil {
			// not port come with request host
			aclhost = string(reqHost)
		}
		if err := h.DomainACL(string(aclhost)); err != nil {
			ctx.Response.SetStatusCode(fasthttp.StatusForbidden)
			log.Printf("ServerHandler, (%s <= %s), access deny to host: %s\n", ctx.LocalAddr(), ctx.RemoteAddr(), aclhost)
			return
		}
		if next != nil {
			next(ctx)
		}
		return
	}
}

// HTTPChallengeHandler return a fasthttp.RequestHandler which use for handle ACME HTTP challenge,
// only requests to "/.well-known/acme-challenge/" should be route to this handler.
func (h *ServerImp) HTTPChallengeHandler(am *certmagic.ACMEManager, next http.HandlerFunc) fasthttp.RequestHandler {
	mux := http.NewServeMux()
	if next == nil {
		// use default handler
		next = func(w http.ResponseWriter, req *http.Request) {
			scheme := req.Header.Get("x-fasthttp-scheme")
			if len(scheme) == 0 {
				scheme = "http"
			}
			msg := fmt.Sprintf("httpChallengeLogger: unhandled ACME HTTP Challenge request, local address %s, remote address %s, URL %s\n", req.Header.Get("x-fasthttp-localaddr"), req.RemoteAddr, scheme+"://"+req.Host+req.URL.String())
			fmt.Fprintf(w, msg)
			log.Printf(msg)

			w.WriteHeader(http.StatusBadRequest)
		}
	}
	mux.HandleFunc("/", next)
	httpChallengeHandler := fasthttpadaptor.NewFastHTTPHandler(am.HTTPChallengeHandler(mux))
	return func(ctx *fasthttp.RequestCtx) {
		log.Printf("HTTPChallengeHandler: (%s <= %s), token: %s, URL %q(%q). LastURI is %q. Counter is %d", ctx.LocalAddr(), ctx.RemoteAddr(), ctx.UserValue("token"), ctx.Path(), ctx.Request.URI().String(), h.LastURI, h.Counter)

		h.mux.Lock()

		h.LastURI = string(ctx.Path())
		h.Counter++
		h.mux.Unlock()

		httpChallengeHandler(ctx)
	}
}

// PrefixRedirectHandler return a fasthttp.RequestHandler which trim the prefix from request host and redirect to new host,
// if prefix not found, will pass request to next handler.
func (h *ServerImp) PrefixRedirectHandler(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {

		log.Printf("PrefixRedirectHandler: (%s <= %s), requested path is %q(%q). LastURI is %q. Counter is %d", ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String(), h.LastURI, h.Counter)

		h.mux.Lock()

		h.LastURI = string(ctx.Path())
		h.Counter++
		h.mux.Unlock()

		reqHost := ctx.Host()

		for _, prefix := range h.TrimList {
			log.Printf("PrefixRedirectHandler: trim %s vs req %s, (%s <= %s)\n", prefix, reqHost, ctx.LocalAddr(), ctx.RemoteAddr())
			if host := bytes.TrimPrefix(reqHost, prefix); bytes.Compare(host, reqHost) != 0 {
				// Request host has www. prefix. Redirect to host with www. trimmed.

				ctx.Redirect(string(ctx.URI().Scheme())+"://"+string(host)+string(ctx.RequestURI()), fasthttp.StatusFound)
				ctx.SetUserValue("MagicRedirect", prefix)
				log.Printf("PrefixRedirectHandler: trim %s, (%s <= %s), redirected to %q\n", prefix, ctx.LocalAddr(), ctx.RemoteAddr(), string(ctx.URI().Scheme())+"://"+string(host)+string(ctx.RequestURI()))
				return
			}
		}

		if next != nil {
			next(ctx)
		}
		return
	}
}

// RedirectToTLSHandler return a fasthttp.RequestHandler which redirect a http request to https
func (h *ServerImp) RedirectToTLSHandler() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		log.Printf("RedirectToTLSHandler(%s <= %s), requested path is %q(%q). LastURI is %q. Counter is %d", ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String(), h.LastURI, h.Counter)

		// Todo: should we check this ?
		if bytes.Compare(ctx.URI().Scheme(), []byte("https")) == 0 {
			log.Fatalf("can not use RedirectToTLSHandler with tls/https requests")
		}

		h.mux.Lock()
		h.LastURI = string(ctx.Path())
		h.Counter++
		h.mux.Unlock()

		reqHost := ctx.Host()

		var newhost string
		var err error
		newhost, _, err = net.SplitHostPort(string(reqHost))

		if err != nil {
			// not port come with request host
			newhost = string(reqHost)
		}

		// https always run on port 443
		ctx.Redirect("https://"+newhost+string(ctx.RequestURI()), fasthttp.StatusFound)
		ctx.SetUserValue("MagicRedirect", "tls")
		log.Printf("RedirectToTLSHandler(%s <= %s), redirected to %q\n", ctx.LocalAddr(), ctx.RemoteAddr(), "https://"+newhost+string(ctx.RequestURI()))
		return
	}
}

// PrefixTLSRedirectHandler return a fasthttp.RequestHandler which redirect a http request to https, and trim the prefix from request host and redirect to new host,
// if prefix not found, will pass request to next handler.
func (h *ServerImp) PrefixTLSRedirectHandler() fasthttp.RequestHandler {
	return h.PrefixRedirectHandler(h.RedirectToTLSHandler())
}

// MagicServerImp return a fasthttp.RequestHandler which call redirect handler and return on redirected,
// otherwise call next
func (h *ServerImp) MagicServerImp(redirect, next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		redirect(ctx)
		rdr := ctx.UserValue("MagicRedirect")
		if rdr != nil {
			log.Printf("MagicServerImp: %s, (%s <= %s)\n", rdr.([]byte), ctx.LocalAddr(), ctx.RemoteAddr())
			return
		}
		if next != nil {
			next(ctx)
		}
		return
	}
}

// ServerControlHandler process shutdown command from remote
func (h *ServerImp) ServerControlHandler(ctx *fasthttp.RequestCtx) {
	tokenOk := bytes.Compare(h.CtrlToken, []byte(fmt.Sprintf("%v", ctx.UserValue("token"))))
	log.Printf("serverControlHandler: token %s == %s = %v, (%s <= %s), requested path is %q(%q). LastURI is %q. Counter is %d", h.CtrlToken, ctx.UserValue("token"), tokenOk, ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String(), h.LastURI, h.Counter)
	if len(h.CtrlToken) > 0 && tokenOk == 0 {
		log.Printf("serverControlHandler: shutting down server ...\n")
		fmt.Fprintf(ctx, "serverControlHandler: shutting down server ...\n")
		ctx.SetStatusCode(fasthttp.StatusOK)

		//
		go func() {
			time.Sleep(time.Millisecond * 100)
			syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		}()

	} else {
		log.Printf("serverControlHandler: access denied\n")
		fmt.Fprintf(ctx, "serverControlHandler: access denied\n")
		ctx.SetStatusCode(fasthttp.StatusForbidden)
	}
}

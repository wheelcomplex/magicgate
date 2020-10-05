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

// ServerImp redirect HTTP requests to HTTPS
type ServerImp struct {
	LastURI  string
	Counter  int64
	CtlToken []byte

	Domains           []string
	WildcardDomains   []string
	DefaultServerName string
	TrimList          [][]byte
	// Todo: add command line flags

	mux sync.Mutex
}

// DomainACL do ACL on access host
func (h *ServerImp) DomainACL(name string) error {

	if len(h.Domains) == 0 && len(h.WildcardDomains) == 0 {
		log.Printf("DomainACL, allow any domains: %s\n", name)
		return nil
	}

	isIP := IsAllDotNumber(name)

	// Todo: more effection way to check for massive domains
	for _, oneDomain := range h.Domains {
		if name == oneDomain {
			log.Printf("DomainACL, match normal domain: %s\n", name)
			return nil
		}
		if isIP && oneDomain == "0.0.0.0" {
			log.Printf("DomainACL, match IP(wildcard): %s\n", name)
			return nil
		}
		log.Printf("DomainACL, MISMATCH normal domain (%s): %s\n", oneDomain, name)
	}

	for _, oneDomain := range h.WildcardDomains {
		if strings.HasSuffix(name, oneDomain) {
			log.Printf("DomainACL, match WILDCARD domain (*%s): %s\n", oneDomain, name)
			return nil
		}
		log.Printf("DomainACL, MISMATCH WILDCARD domain (*%s): %s\n", oneDomain, name)
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
			msg := fmt.Sprintf("httpChallengeLogger: unhandled ACME HTTP Challenge request, remote address %s, URL %s\n", req.RemoteAddr, scheme+"://"+req.Host+req.URL.String())
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
	tokenOk := bytes.Compare(h.CtlToken, []byte(fmt.Sprintf("%v", ctx.UserValue("token"))))
	log.Printf("serverControlHandler: token %s == %s = %v, (%s <= %s), requested path is %q(%q). LastURI is %q. Counter is %d", h.CtlToken, ctx.UserValue("token"), tokenOk, ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String(), h.LastURI, h.Counter)
	if len(h.CtlToken) > 0 && tokenOk == 0 {
		log.Printf("serverControlHandler: shutting down server ...\n")
		fmt.Fprintf(ctx, "serverControlHandler: shutting down server ...\n")
		time.Sleep(time.Second)
		syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	} else {
		log.Printf("serverControlHandler: happy running ...\n")
		fmt.Fprintf(ctx, "serverControlHandler: happy running ...\n")
	}
}

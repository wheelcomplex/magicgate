//

package magicgate

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

// RedirectHandler redirect HTTP requests to HTTPS
type RedirectHandler struct {
	LastURI  string
	Counter  int64
	CtlToken []byte
	mux      sync.Mutex
}

// HTTPChallengeHandler return a fasthttp.RequestHandler which use for handle ACME HTTP challenge,
// only requests to "/.well-known/acme-challenge/" should be route to this handler.
func (h *RedirectHandler) HTTPChallengeHandler(am *certmagic.ACMEManager, next http.HandlerFunc) fasthttp.RequestHandler {
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
func (h *RedirectHandler) PrefixRedirectHandler(prefixList [][]byte, next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {

		log.Printf("PrefixRedirectHandler: (%s <= %s), requested path is %q(%q). LastURI is %q. Counter is %d", ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String(), h.LastURI, h.Counter)

		h.mux.Lock()

		h.LastURI = string(ctx.Path())
		h.Counter++
		h.mux.Unlock()

		reqHost := ctx.Host()

		for _, prefix := range prefixList {
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
func (h *RedirectHandler) RedirectToTLSHandler() fasthttp.RequestHandler {
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
func (h *RedirectHandler) PrefixTLSRedirectHandler(prefixList [][]byte) fasthttp.RequestHandler {
	return h.PrefixRedirectHandler(prefixList, h.RedirectToTLSHandler())
}

// MagicRedirectHandler return a fasthttp.RequestHandler which call redirect handler and return on redirected,
// otherwise call next
func (h *RedirectHandler) MagicRedirectHandler(redirect, next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		redirect(ctx)
		rdr := ctx.UserValue("MagicRedirect")
		if rdr != nil {
			log.Printf("MagicRedirectHandler: %s, (%s <= %s)\n", rdr.([]byte), ctx.LocalAddr(), ctx.RemoteAddr())
			return
		}
		if next != nil {
			next(ctx)
		}
		return
	}
}

// ServerControlHandler process shutdown command from remote
func (h *RedirectHandler) ServerControlHandler(ctx *fasthttp.RequestCtx) {
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

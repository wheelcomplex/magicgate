//

package magicgate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/valyala/fasthttp"
)

// DataCache implements internal data/cache management
type DataCache struct {
	tokens map[string]uint64                 // [token]uid
	userDB map[uint64]map[string]interface{} // [uid]map[class]user data interface
	mux    sync.Mutex
}

// NewDataCache return a DataCache with input token list
func NewDataCache(tokens map[string]string) *DataCache {
	h := &DataCache{
		Tokens:   tokens,
		Contents: make(map[string]string),
	}
	for tk := range h.Tokens {
		h.Contents[tk] = "-"
	}
	return h
}

// DataCacheHandler return a fasthttp.RequestHandler which register client ip/domain to server
func (h *DataCache) getClientNameByToken(ctx *fasthttp.RequestCtx) (token string, name string, ok bool) {

	token = string([]byte(fmt.Sprintf("%v", ctx.UserValue("token"))))

	if len(token) == 0 {
		return token, name, ok
	}

	token = strings.ToLower(token)

	name, ok = h.Tokens[token]
	return token, name, ok
}

// Todo: check server ctrl token first
// Todo: use fastcache

// DataCacheHandler return a fasthttp.RequestHandler which register client ip/domain to server
func (h *DataCache) DataCacheHandler() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		log.Printf("DataCacheHandler(%s <= %s), requested path is %q(%q).", ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String())

		h.mux.Lock()
		defer h.mux.Unlock()

		tk, name, ok := h.getClientNameByToken(ctx)

		msg := fmt.Sprintf("DataCacheHandler: token %s, name %s, ok %v, (%s <= %s), requested path is %q(%q)", tk, name, ok, ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String())
		if ok {

			value := []byte(fmt.Sprintf("%v", ctx.UserValue("value")))

			if len(value) == 0 {
				value = []byte("-")
			}

			if bytes.Compare(value, []byte("_REG_IP_")) == 0 {
				value = []byte(ctx.RemoteAddr().String())
			}

			// save content
			h.Contents[tk] = string(value)

			msg += ", register value: " + string(value)

			if _, err := ctx.WriteString(msg + " OK\n"); err != nil {
				log.Printf(msg + ", write to client failed: " + fmt.Sprintf("%v", err) + "\n")
				ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			} else {
				log.Printf(msg + ", OK\n")
				ctx.SetStatusCode(fasthttp.StatusOK)
			}
		} else {
			if _, err := ctx.WriteString(msg + ", DENIED\n"); err != nil {
				log.Printf(msg + " write to client failed: " + fmt.Sprintf("%v", err) + "\n")
				ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			} else {
				log.Printf(msg + ", DENIED\n")
				ctx.SetStatusCode(fasthttp.StatusForbidden)
			}
		}
		return
	}
}

// JSONContentHandler return a fasthttp.RequestHandler which show current contents to client in JSON
func (h *DataCache) JSONContentHandler() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		log.Printf("JSONContentHandler(%s <= %s), requested path is %q(%q).", ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String())

		h.mux.Lock()
		defer h.mux.Unlock()

		tk, name, ok := h.getClientNameByToken(ctx)

		msg := fmt.Sprintf("JSONContentHandler: token %s, name %s, ok %v, (%s <= %s), requested path is %q(%q)", tk, name, ok, ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String())
		if ok {
			output := map[string]map[string]string{
				"Tokens":   h.Tokens,
				"Contents": h.Contents,
			}
			if body, err := json.Marshal(output); err == nil {
				if _, err := ctx.Write(body); err != nil {
					log.Printf(msg + " write to client failed: " + fmt.Sprintf("%v", err) + "\n")
					ctx.SetStatusCode(fasthttp.StatusInternalServerError)
				} else {
					log.Printf(msg + " OK\n")
					ctx.SetStatusCode(fasthttp.StatusOK)
				}
			} else {
				log.Printf(msg + " write to client failed: " + fmt.Sprintf("%v", err) + "\n")
				ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			}
		} else {
			if _, err := ctx.WriteString(msg + " DENIED\n"); err != nil {
				log.Printf(msg + " write to client failed: " + fmt.Sprintf("%v", err) + "\n")
				ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			} else {
				log.Printf(msg + " DENIED\n")
				ctx.SetStatusCode(fasthttp.StatusForbidden)
			}
		}
		return
	}
}

//

package magicgate

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/valyala/fasthttp"
	"github.com/wheelcomplex/fastcache"
	"github.com/wheelcomplex/magicgate/utils"
	"github.com/wheelcomplex/rawproxy"
)

var (
	// HTTPContentType is HTTP Content-Type header key
	HTTPContentType = []byte("Content-Type")

	// ApplicationJSON is HTTP Content-Type header value
	ApplicationJSON = []byte("application/json")
)

// DataCache implements internal data/cache management
type DataCache struct {
	tokenfc   *fastcache.Cache
	contentfc *fastcache.Cache
	cacheDir  string
	mux       sync.Mutex
}

// getUIDInfo get key:value from contents k,v buffer,
// contents  map[uint64]map[string]string // [uid]map[class]user data interface
func (dc *DataCache) getUIDInfo(k, v []byte) (uid uint64, key, value string, ok bool) {
	// uid + "\n" + key as fastcache key
	tmpArr := bytes.Split(k, []byte("\n"))
	if len(tmpArr) < 2 {
		log.Printf("getUIDInfo, contents, VisitAllEntries callback: INVALID contents key %q, value %q\n", string(k), string(v))
		return
	}
	uid = uint64(binary.LittleEndian.Uint64(tmpArr[0]))
	key = string(tmpArr[1])
	value = string(v)
	log.Printf("getUIDInfo, restored: uid %d, key %s, value %s\n", uid, key, value)
	return uid, key, value, true
}

// getTokenInfo get token:uid from tokens k,v buffer,
// tokens  map[string]uint64
func (dc *DataCache) getTokenInfo(k, v []byte) (tk string, uid uint64) {
	tk = string(k)
	uid = uint64(binary.LittleEndian.Uint64(v))
	log.Printf("getTokenInfo, restored: token %s, uid %d\n", tk, uid)
	return tk, uid
}

// LoadDataCache load DataCache from saved fastcache dir,
// or create new on fatal.
// size counted in bytes.
func LoadDataCache(cacheDir string, createOnFatal bool, size int) (dc *DataCache, err error) {
	cacheDir, _ = filepath.Abs(cacheDir)
	dc = &DataCache{
		cacheDir: cacheDir,
	}

	// load fastcache
	if dc.tokenfc, err = dc.loadFastCache(cacheDir+"/tokens/", createOnFatal, size); err != nil {
		log.Printf("error in load fastcache dir: %s", err)
		return nil, err
	}

	// check tokens,
	// tokens map[string]uint64
	dc.tokenfc.VisitAllEntries(func(k, v []byte) error {
		log.Printf("LoadDataCache, tokens, VisitAllEntries callback: key %q, value %q", string(k), string(v))
		tk, uid := dc.getTokenInfo(k, v)
		log.Printf("LoadDataCache, tokens, restored: token %q, uid %d", tk, uid)
		return nil
	})

	if dc.contentfc, err = dc.loadFastCache(cacheDir+"/contents/", createOnFatal, size); err != nil {
		log.Printf("error in load fastcache dir: %s", err)
		return nil, err
	}

	var modifyOnLoad bool

	// check contents
	// contents  map[uint64]map[string]string // [uid]map[class]user data interface
	dc.contentfc.VisitAllEntries(func(k, v []byte) error {
		log.Printf("LoadDataCache, contents, VisitAllEntries callback: key %q, value %s\n", string(k), string(v))
		uid, key, value, ok := dc.getUIDInfo(k, v)
		if ok {
			log.Printf("LoadDataCache, contents, restored: uid %d, key %s, value %s\n", uid, key, value)
		} else {
			log.Printf("LoadDataCache, contents, removed: uid %d, key %s, value %s\n", uid, key, value)
			dc.contentfc.Del(k)
			modifyOnLoad = true
		}
		return nil
	})

	if modifyOnLoad {
		dc.SaveToDir("")
	}

	return dc, nil
}

// loadFastCache saved fastcache dir,
// or create new on fatal.
// size counted in bytes.
func (dc *DataCache) loadFastCache(cacheDir string, createOnFatal bool, size int) (fc *fastcache.Cache, err error) {
	cacheDir, _ = filepath.Abs(cacheDir)
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		log.Printf("error in create fastcache dir: %s", err)
		return nil, err
	}
	if fc, err = fastcache.LoadFromFile(cacheDir); err != nil {
		if createOnFatal {
			log.Printf("try to create new cache while error in load fastcache dir: %s", err)
			fc = fastcache.New(size)
			if err := fc.SaveToFile(cacheDir); err != nil {
				log.Printf("error in save fastcache dir (createOnFatal): %s", err)
				return nil, err
			}
			log.Printf("new cache created: %s", cacheDir)
			err = nil
		} else {
			log.Printf("error in load fastcache dir: %s", err)
			return nil, err
		}
	}

	return fc, err
}

// SaveToDir flush current DataCache data into disk cacheDir,
// if cacheDir is empty, will save to the dir which used on loading.
func (dc *DataCache) SaveToDir(cacheDir string) (err error) {
	if cacheDir == "" {
		cacheDir = dc.cacheDir
	}
	if cacheDir == "" {
		err = fmt.Errorf("invalid dir (empty) parameter for save fastcache")
		log.Printf("%s\n", err)
		return err
	}
	cacheDir, _ = filepath.Abs(cacheDir)

	// save fastcache
	if err = dc.tokenfc.SaveToFile(cacheDir + "/tokens/"); err != nil {
		log.Printf("error in save fastcache dir: %s", err)
		return err
	}

	if err = dc.contentfc.SaveToFile(cacheDir + "/contents/"); err != nil {
		log.Printf("error in save fastcache dir: %s", err)
		return err
	}

	return err
}

// SetToken set token:uid into tokens
func (dc *DataCache) SetToken(tk string, uid uint64) {
	u64Buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(u64Buf, uid)
	dc.tokenfc.Set([]byte(tk), u64Buf)
	log.Printf("SetToken, %s, %d \n", tk, uid)
}

// SetKeyValue set uid,key,value into contents
func (dc *DataCache) SetKeyValue(uid uint64, key, value string) {

	k := make([]byte, 16)
	binary.LittleEndian.PutUint64(k, uid)
	k = append(k, []byte("\n"+key)...)

	dc.contentfc.Set(k, []byte(value))
	log.Printf("SetKeyValue, uid %d, key %s, value %s \n", uid, key, value)
}

// GetUIDByToken get uid from tokens,
// return ok == true when hit
func (dc *DataCache) GetUIDByToken(tk string) (uid uint64, ok bool) {
	var v []byte
	v, ok = dc.tokenfc.HasGet(nil, []byte(tk))
	if ok {
		_, uid = dc.getTokenInfo([]byte(tk), v)
	}
	log.Printf("GetUIDByToken, %s, %d, %v\n", tk, uid, ok)
	return
}

// GetValue get value from tokens by uid, key,
// return ok == true when hit
func (dc *DataCache) GetValue(uid uint64, key string) (value string, ok bool) {
	// uid + "\n" + key as fastcache key

	k := make([]byte, 16)
	binary.LittleEndian.PutUint64(k, uid)
	k = append(k, []byte("\n"+key)...)

	var v []byte
	v, ok = dc.contentfc.HasGet(nil, k)
	if ok {
		uid, _, value, ok = dc.getUIDInfo(k, v)
	}
	log.Printf("GetValue, uid %d, key %s, value %s, %v\n", uid, key, value, ok)
	return
}

// MergeTokens DataCache with input token list,
// duplicated tokens will be ignored if overwrite flag is false.
// return replaced tokens
func (dc *DataCache) MergeTokens(tokens map[string]uint64, overwrite bool) (replaced map[string]uint64) {
	replaced = make(map[string]uint64)
	for tk, uid := range tokens {
		v, ok := dc.tokenfc.HasGet(nil, []byte(tk))
		if ok {
			// already existed
			oldUID := uint64(binary.LittleEndian.Uint64(v))
			if overwrite && oldUID != uid {
				log.Printf("MergeTokens, overwrite exist token %s, %d => %s, %d\n", tk, oldUID, tk, uid)
				replaced[tk] = oldUID
			} else {
				log.Printf("MergeTokens, skipped exist token %s, %d # %s, %d\n", tk, oldUID, tk, uid)
				continue
			}
		}
		u64Buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(u64Buf, uid)
		dc.tokenfc.Set([]byte(tk), u64Buf)
		log.Printf("MergeTokens, save token %s, %d \n", tk, uid)
	}
	dc.SaveToDir(dc.cacheDir)
	return replaced
}

// Todo: check server ctrl token first
// Todo: use fastcache

// checkToken verify access token from client,
// return uid, true for pass
func (dc *DataCache) checkToken(ctx *fasthttp.RequestCtx) (tk string, uid uint64, ok bool) {

	tk = string([]byte(fmt.Sprintf("%v", ctx.UserValue("token"))))

	tk = strings.ToLower(tk)

	// check token
	uid, ok = dc.GetUIDByToken(tk)
	if ok {
		return
	}
	if _, err := ctx.WriteString("ACCESS DENIED\n"); err != nil {
		log.Printf("checkToken, write to client failed: " + fmt.Sprintf("%v", err) + "\n")
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
	} else {
		log.Printf("checkToken, DENIED: " + tk + "\n")
		ctx.SetStatusCode(fasthttp.StatusForbidden)
	}
	return
}

// DataCacheSetKVHandler return a fasthttp.RequestHandler which can update dataCache by token/key/value,
// tlsRouter.GET("/api/db/set/:token/:key/:value", dc.DataCacheSetKVHandler())
func (dc *DataCache) DataCacheSetKVHandler() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {

		dc.mux.Lock()
		defer dc.mux.Unlock()

		// check token
		tk, uid, ok := dc.checkToken(ctx)
		if !ok {
			return
		}

		key := string([]byte(fmt.Sprintf("%v", ctx.UserValue("key"))))

		value := string([]byte(fmt.Sprintf("%v", ctx.UserValue("value"))))

		log.Printf("DataCacheSetKVHandler, token %s, key %s, value %s, (%s <= %s), requested path is %q(%q).", tk, key, value, ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String())

		var msg string

		msg = fmt.Sprintf("DataCacheSetKVHandler: token %s, uid %d, ok %v, (%s <= %s), requested path is %q(%q)", tk, uid, ok, ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String())

		// magic value
		if strings.Compare(value, "_REG_IP_") == 0 {
			value = ctx.RemoteAddr().String()
		}

		// save content
		dc.SetKeyValue(uid, key, value)

		msg += ", set value: " + value

		if _, err := ctx.WriteString(msg + " OK\n"); err != nil {
			log.Printf(msg + ", write to client failed: " + fmt.Sprintf("%v", err) + "\n")
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		} else {
			log.Printf(msg + ", OK\n")
			ctx.SetStatusCode(fasthttp.StatusOK)
		}

		return
	}
}

// DataCacheGetKVHandler return a fasthttp.RequestHandler which can update dataCache by token/key/value,
// tlsRouter.GET("/api/db/set/:token/:key/:value", dc.DataCacheGetKVHandler())
func (dc *DataCache) DataCacheGetKVHandler() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {

		dc.mux.Lock()
		defer dc.mux.Unlock()

		// check token
		tk, uid, ok := dc.checkToken(ctx)
		if !ok {
			return
		}

		key := string([]byte(fmt.Sprintf("%v", ctx.UserValue("key"))))

		// get content
		value, ok := dc.GetValue(uid, key)

		// magic value
		if strings.Compare(key, "_MY_IP_") == 0 {
			value = ctx.RemoteAddr().String()
		}

		log.Printf("DataCacheGetKVHandler, token %s, key %s, value %s, (%s <= %s), requested path is %q(%q).", tk, key, value, ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String())

		var msg string

		msg = fmt.Sprintf("DataCacheGetKVHandler: token %s, uid %d, ok %v, (%s <= %s), requested path is %q(%q)", tk, uid, ok, ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String())

		msg += ", get value: " + value

		if _, err := ctx.WriteString(msg + " OK\n"); err != nil {
			log.Printf(msg + ", write to client failed: " + fmt.Sprintf("%v", err) + "\n")
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		} else {
			log.Printf(msg + ", OK\n")
			ctx.SetStatusCode(fasthttp.StatusOK)
		}

		return
	}
}

// DataCacheListKVHandler return a fasthttp.RequestHandler which can list dataCache by token/key in JSON text,
// tlsRouter.GET("/api/db/list/:token/:key", dc.DataCacheListKVHandler())
func (dc *DataCache) DataCacheListKVHandler() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {

		dc.mux.Lock()
		defer dc.mux.Unlock()

		// check token
		tk, uid, ok := dc.checkToken(ctx)
		if !ok {
			return
		}

		key := string([]byte(fmt.Sprintf("%v", ctx.UserValue("key"))))

		value := string([]byte(fmt.Sprintf("%v", ctx.UserValue("value"))))

		tk = strings.ToLower(tk)

		log.Printf("DataCacheListKVHandler, token %s, key %s, value %s, (%s <= %s), requested path is %q(%q).", tk, key, value, ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String())

		var msg string

		msg = fmt.Sprintf("DataCacheListKVHandler: token %s, uid %d, ok %v, (%s <= %s), requested path is %q(%q)", tk, uid, ok, ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String())

		var done bool

		arr := make(map[string]string)

		// restore to contents
		// contents  map[uint64]map[string]string // [uid]map[class]user data interface
		dc.contentfc.VisitAllEntries(func(k, v []byte) error {
			log.Printf("DataCacheListKVHandler, contents, VisitAllEntries callback: key %q, value %s\n", string(k), string(v))
			uid, cacheKey, value, ok := dc.getUIDInfo(k, v)
			if !ok {
				log.Printf("DataCacheListKVHandler, contents, skipped invalid item, VisitAllEntries callback: key %q, value %s\n", string(k), string(v))
				return nil
			}
			switch key {
			case "_ALL_KEYS_":
				// list all value in all keys
				// magic value
				if strings.Compare(cacheKey, "_MY_IP_") == 0 {
					value = ctx.RemoteAddr().String()
				}
				arr[cacheKey] = value

			case "_LIST_KEYS_":
				// list keys only
				arr[cacheKey] = ""
			default:
				// get
				if strings.Compare(cacheKey, key) == 0 {
					arr[key] = value
					// magic value
					if strings.Compare(cacheKey, "_MY_IP_") == 0 {
						value = ctx.RemoteAddr().String()
					}
					// tell fastcache to stop looping
					done = true
				}
			}
			log.Printf("DataCacheListKVHandler, contents, restored: uid %d, key %s, value %s\n", uid, cacheKey, value)
			if done {
				return new(utils.NopError)
			}
			return nil
		})

		msg += ", list value of : " + key

		ctx.Response.Header.SetCanonical(HTTPContentType, ApplicationJSON)

		body, err := json.Marshal(arr)
		if err != nil {
			log.Printf(msg + ", Marshal data failed: " + fmt.Sprintf("%v", err) + "\n")
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		} else {
			if _, err := ctx.Write(body); err != nil {
				log.Printf(msg + ", write to client failed: " + fmt.Sprintf("%v", err) + "\n")
				ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			} else {
				log.Printf(msg + ", OK\n")
				ctx.SetStatusCode(fasthttp.StatusOK)
			}
		}
		return
	}
}

// DataCacheJSONHandler return a fasthttp.RequestHandler which can update dataCache by token/key/JSON
func (dc *DataCache) DataCacheJSONHandler() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		log.Printf("DataCacheHandler(%s <= %s), requested path is %q(%q).", ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String())

		dc.mux.Lock()
		defer dc.mux.Unlock()
		// Todo
		return
	}
}

// JSONContentHandler return a fasthttp.RequestHandler which show current contents to client in JSON
func (dc *DataCache) JSONContentHandler() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		log.Printf("JSONContentHandler(%s <= %s), requested path is %q(%q).", ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String())

		dc.mux.Lock()
		defer dc.mux.Unlock()
		// Todo
		return
	}
}

// ProxyAuthHandler return a fasthttp.RequestHandler which can update proxy setting by token/key/value,
// tlsRouter.GET("/api/db/setproxy/:token/:key/:value", dc.DataCacheSetKVHandler())
func (dc *DataCache) ProxyAuthHandler() rawproxy.ProxyAuthHandler {
	return func(ctx *rawproxy.ProxyCtx) error {
		log.Printf("ProxyAuthHandler(%s <= %s), auth %s\n", ctx.LocalAddr(), ctx.RemoteAddr(), ctx.AuthInfo)
		return nil
	}
}

// DataCacheSetProxyHandler return a fasthttp.RequestHandler which can update proxy setting by token/key/value,
// tlsRouter.GET("/api/db/setproxy/:token/:key/:value", dc.DataCacheSetKVHandler())
func (dc *DataCache) DataCacheSetProxyHandler() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {

		dc.mux.Lock()
		defer dc.mux.Unlock()

		// check token
		tk, uid, ok := dc.checkToken(ctx)
		if !ok {
			return
		}

		key := string([]byte(fmt.Sprintf("%v", ctx.UserValue("key"))))

		value := string([]byte(fmt.Sprintf("%v", ctx.UserValue("value"))))

		log.Printf("DataCacheSetKVHandler, token %s, key %s, value %s, (%s <= %s), requested path is %q(%q).", tk, key, value, ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String())

		var msg string

		msg = fmt.Sprintf("DataCacheSetKVHandler: token %s, uid %d, ok %v, (%s <= %s), requested path is %q(%q)", tk, uid, ok, ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String())

		// magic value
		if strings.Compare(value, "_REG_IP_") == 0 {
			value = ctx.RemoteAddr().String()
		}

		// save content
		dc.SetKeyValue(uid, key, value)

		msg += ", set value: " + value

		if _, err := ctx.WriteString(msg + " OK\n"); err != nil {
			log.Printf(msg + ", write to client failed: " + fmt.Sprintf("%v", err) + "\n")
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		} else {
			log.Printf(msg + ", OK\n")
			ctx.SetStatusCode(fasthttp.StatusOK)
		}

		return
	}
}

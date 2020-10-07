// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"encoding/json"
	"strings"

	"github.com/mholt/acmez/acme"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// FastHTTPChallengeHandler wraps h in a fasthttp.RequestHandler that can solve the ACME
// HTTP challenge. cfg is required, and it must have a certificate
// cache backed by a functional storage facility, since that is where
// the challenge state is stored between initiation and solution.
//
// If a request is not an ACME HTTP challenge, h will be invoked.
// If h is nil, all unhandled HTTP requests will be ignored.
func (am *ACMEManager) FastHTTPChallengeHandler(h fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if am.HandleFastHTTPChallenge(ctx) {
			return
		}
		if h != nil {
			h(ctx)
		}
	}
}

// HandleFastHTTPChallenge uses am to solve challenge requests from an ACME
// server that were initiated by this instance or any other instance in
// this cluster (being, any instances using the same storage am does).
//
// If the HTTP challenge is disabled, this function is a no-op.
//
// If am is nil or if am does not have a certificate cache backed by
// usable storage, solving the HTTP challenge will fail.
//
// It returns true if it handled the request; if so, the response has
// already been written. If false is returned, this call was a no-op and
// the request has not been handled.
func (am *ACMEManager) HandleFastHTTPChallenge(ctx *fasthttp.RequestCtx) bool {
	if am == nil {
		return false
	}
	if am.DisableHTTPChallenge {
		return false
	}
	if !LooksLikeFastHTTPChallenge(ctx) {
		return false
	}
	return am.distributedFastHTTPChallengeSolver(ctx)
}

// distributedFastHTTPChallengeSolver checks to see if this challenge
// request was initiated by this or another instance which uses the
// same storage as am does, and attempts to complete the challenge for
// it. It returns true if the request was handled; false otherwise.
func (am *ACMEManager) distributedFastHTTPChallengeSolver(ctx *fasthttp.RequestCtx) bool {
	if am == nil {
		return false
	}

	host := hostOnly(string(ctx.Host()))

	tokenKey := distributedSolver{acmeManager: am, caURL: am.CA}.challengeTokensKey(host)
	chalInfoBytes, err := am.config.Storage.Load(tokenKey)
	if err != nil {
		if _, ok := err.(ErrNotExist); !ok {
			if am.Logger != nil {
				am.Logger.Error("opening distributed HTTP challenge token file",
					zap.String("host", host),
					zap.Error(err))
			}
		}
		return false
	}

	var challenge acme.Challenge
	err = json.Unmarshal(chalInfoBytes, &challenge)
	if err != nil {
		if am.Logger != nil {
			am.Logger.Error("decoding HTTP challenge token file (corrupted?)",
				zap.String("host", host),
				zap.String("token_key", tokenKey),
				zap.Error(err))
		}
		return false
	}

	return am.answerFastHTTPChallenge(ctx, challenge)
}

// answerFastHTTPChallenge solves the challenge with chalInfo.
// Most of this code borrowed from xenolf 's built-in HTTP-01
// challenge solver in March 2018.
func (am *ACMEManager) answerFastHTTPChallenge(ctx *fasthttp.RequestCtx, challenge acme.Challenge) bool {
	challengeReqPath := challenge.HTTP01ResourcePath()
	if string(ctx.Path()) == challengeReqPath &&
		strings.EqualFold(hostOnly(string(ctx.Host())), challenge.Identifier.Value) && // mitigate DNS rebinding attacks
		ctx.IsGet() {
		ctx.Response.Header.Set("Content-Type", "text/plain")
		ctx.Write([]byte(challenge.KeyAuthorization))
		ctx.SetStatusCode(fasthttp.StatusOK)
		if am.Logger != nil {
			am.Logger.Info("served key authentication",
				zap.String("identifier", challenge.Identifier.Value),
				zap.String("challenge", "http-01"),
				zap.String("remote", ctx.RemoteAddr().String()))
		}
		return true
	}
	return false
}

// LooksLikeFastHTTPChallenge returns true if r looks like an ACME
// HTTP challenge request from an ACME server.
func LooksLikeFastHTTPChallenge(ctx *fasthttp.RequestCtx) bool {
	return ctx.IsGet() && strings.HasPrefix(string(ctx.Path()), challengeBasePath)
}

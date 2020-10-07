module magicgate

go 1.16

// go mod edit -replace github.com/pselle/bar=/Users/pselle/Projects/bar

// replace github.com/caddyserver/certmagic => /home/david/home/wheelcomplex/certmagic

// replace github.com/caddyserver/certmagic v0.12.0 => github.com/wheelcomplex/certmagic v0.12.0

// replace github.com/wheelcomplex/certmagic => /home/david/home/wheelcomplex/certmagic

// replace github.com/valyala/fasthttp v1.16.0 => github.com/wheelcomplex/fasthttp 0.0.0-20201004003347-689f81a0c599

replace github.com/valyala/fasthttp v1.16.0 => /home/david/home/wheelcomplex/fasthttp

replace github.com/caddyserver/certmagic v0.12.0 => /home/david/home/wheelcomplex/magicgate/certmagic

replace github.com/wheelcomplex/certmagic v0.12.0 => /home/david/home/wheelcomplex/magicgate/certmagic

replace github.com/mholt/acmez v0.1.1 => /home/david/home/wheelcomplex/magicgate/acmez

// replace github.com/VictoriaMetrics/fastcache v1.5.7 => /home/david/home/wheelcomplex/magicgate/fastcache

replace github.com/wheelcomplex/fastcache v1.5.7 => /home/david/home/wheelcomplex/magicgate/fastcache

require (
	github.com/buaazp/fasthttprouter v0.1.1
	github.com/caddyserver/certmagic v0.12.0
	github.com/klauspost/cpuid v1.3.1 // indirect
	github.com/miekg/dns v1.1.31 // indirect
	github.com/valyala/fasthttp v1.16.0
	github.com/wheelcomplex/fastcache v1.5.7
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	golang.org/x/sys v0.0.0-20201006155630-ac719f4daadf // indirect
)


# debug go app which want to run as root and bind to port 443/80 by delve remote debugging in vscode

## in most cases it is difficult to debug go app which have to bind on tcp port 443, because it requires root privilege, and vscode should not be run under root privilege

## thanks

* <https://golangforall.com/en/post/go-docker-delve-remote-debug.html>

## install delve

* go get -u github.com/go-delve/delve/cmd/dlv

* <https://github.com/go-delve/delve>

## run go build to get binary

## start dlv with app and accept debug client on port 2345

```bash
sudo ${GOPATH}/bin//dlv --continue --listen=:2345 --headless=true --log=true --log-output=debugger --accept-multiclient --api-version=2 exec <app binary to debug> [-- app parameters]
```

* use sudo to allow app bind to port 443/80

## example

```bash
sudo /home/david/gopkg/bin/dlv --continue --listen=:2345 --headless=true --log=true --log-output=debugger --accept-multiclient --api-version=2 exec ./magicgate -- --domains="*.example.dev" --addrTLS="0.0.0.0:443" --addr="0.0.0.0:80" --defaultservername=default.example.dev --trimlist="www.,default."
```

## create launch.json for vscode debug

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Attach",
            "type": "go",
            "request": "attach",
            "mode": "remote",
            "remotePath": "",
            "port": 2345,
            "host": "127.0.0.1",
            "showLog": true,
            "trace": "log",
            "logOutput": "rpc"
        }
    ]
}

```

## open the go source file in vscode, mark some breakpoint, and press \<F5> to start debug

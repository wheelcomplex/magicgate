# work with let's encrypt staging

* note: work with wget only, no firefox/chrome.

* [Installing a root/CA Certificate](https://askubuntu.com/a/94861/969264)

* download [staging root CA](https://letsencrypt.org/certs/fakeleintermediatex1.pem) from [Let's Encrypt](https://letsencrypt.org/docs/staging-environment/)

* convert to crt

```bash
openssl x509 -in fakeleintermediatex1.pem -inform PEM -out fakeleintermediatex1.crt
```

* install

```bash
sudo mkdir /usr/share/ca-certificates/extra/ && \
sudo cp -av fakeleintermediatex1.crt /usr/share/ca-certificates/extra/
```

* update system, remember to enable "extra/fakeleintermediatex1.crt" in the dialog

```bash
sudo dpkg-reconfigure ca-certificates
```

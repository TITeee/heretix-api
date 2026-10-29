# Serving the API over HTTPS

The API listens on plain HTTP. The API key (`x-api-key`) and the admin key cross the network in clear text unless a reverse proxy in front terminates TLS. Put one in front before a client reaches the API over a network you do not fully trust. This page uses [Caddy](https://caddyserver.com/); an nginx equivalent follows.

The compose file starts no proxy: it needs your domain and certificate. The database port is not published, and the app port is yours to restrict, as below.

## 1. Publish the app to the proxy only

By default the app port answers on every interface. Bind it to the loopback address, so only the proxy on the same host reaches it. In `.env`:

```bash
BIND_ADDRESS=127.0.0.1
```

heretix-management and heretix-cli then reach the API through the proxy's `https://` address. A heretix-management on the same host that keeps `HERETIX_API_URL=http://host.docker.internal:5000` can no longer reach a port bound to loopback: point it at the proxy's address instead.

## 2. Caddy

```caddyfile
api.example.com {
	encode zstd gzip
	reverse_proxy 127.0.0.1:5000
}
```

Caddy gets and renews the certificate by itself (the name must resolve to the host and ports 80 and 443 must be open). It sets `X-Forwarded-For` and `X-Forwarded-Proto`, and discards any `X-Forwarded-*` a client sent. Without a public name, `tls internal` makes Caddy sign with its own CA; clients must trust that CA's root certificate.

### HSTS

Once browsers trust the certificate, tell them to use HTTPS only (it matters for the dashboard; other clients ignore it):

```caddyfile
	header Strict-Transport-Security "max-age=31536000"
```

The API does not send this header itself. A browser that has seen it refuses the "continue anyway" click-through on a certificate warning, so do not add it while the certificate is self-signed or untrusted. Start with a short `max-age` (`300`) to check, then raise it.

## nginx

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;
    ssl_certificate     /etc/ssl/api.example.com.crt;
    ssl_certificate_key /etc/ssl/api.example.com.key;

    client_max_body_size 2m;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # A batch search with many findings can take minutes on a cold database.
        proxy_read_timeout 300s;
        # add_header Strict-Transport-Security "max-age=31536000" always;
    }
}

server {
    listen 80;
    server_name api.example.com;
    return 301 https://$host$request_uri;
}
```

## 3. Set `TRUST_PROXY`

Behind a proxy every request comes from the proxy's address, so the per-address rate limits would count all clients as one. Set `TRUST_PROXY` in `.env` so the API reads the client from `X-Forwarded-For`:

```bash
TRUST_PROXY=172.16.0.0/12
```

The value is the address the **API sees the proxy at**, not the proxy's public address:

- A proxy on the host, reaching the published port: the API sees Docker's gateway address, usually in `172.16.0.0/12` (`docker network inspect heretix-api_default` shows the exact one).
- A proxy in a container on the Compose network: that container's address or the network's range.

Leave it unset when there is no proxy: a client could otherwise pick its own address with that header. With the wrong value every client shares the proxy's one budget (`RATE_LIMIT_MAX` requests a minute).

## Other things to set

- `POSTGRES_PASSWORD`: the compose file falls back to `changeme` when it is unset. Set a long random value in `.env` before the first start. It is applied only when the database volume is created: to change it later, `ALTER USER postgres PASSWORD '...'` in the database as well as in `.env`.
- Keep port 5432 closed: the compose file does not publish it, so leave it that way.
- `API_KEY` and `ADMIN_API_KEY`: see [operations.md](operations.md#environment-variables). Send them only over HTTPS.

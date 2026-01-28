# dwlabbind

Object-oriented BIND server management with XML configuration and optional REST API.

## Quick start

Initialize a server config:

```bash
python -m dwlabbind.runner init --name ns1 --ip 192.0.2.10 --role master --config ./bind.xml
```

By default, configs are stored in an OS-specific config directory. Override with `--config` or `DWLABBIND_CONFIG`.

Add a zone:

```bash
python -m dwlabbind.runner add-zone --config ./bind.xml --name example.com --type master --file db.example.com
```

Serve REST API:

```bash
python -m dwlabbind.runner serve-api --config ./bind.xml --host 127.0.0.1 --port 8080
```

## REST API endpoints

- `GET /server` returns the current configuration as JSON
- `POST /server` replaces the configuration with JSON payload
- `POST /zones` adds a zone with JSON payload
- `DELETE /zones/{name}` removes a zone by name
- `POST /import` imports an existing server config (supports `bind9`, `powerdns`, `msdns`)

## Import notes

- `bind9`: `config_path` should point to `named.conf`.
- `powerdns`: `config_path` should point to `pdns.conf` with `bind-config` set.
- `msdns`: `config_path` can be a directory of `.dns` files or a `|`-delimited zone list file.

## API import example

```bash
curl -X POST http://127.0.0.1:8080/import \
  -H 'Content-Type: application/json' \
  -d '{
    "server_type": "bind9",
    "config_path": "/etc/bind/named.conf",
    "name": "ns1",
    "ip": "192.0.2.10",
    "port": 53,
    "role": "master",
    "version": "9.18"
  }'
```

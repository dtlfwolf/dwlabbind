# dwlabbind

Object-oriented BIND server management with XML configuration and optional REST API.

## Quick start

Initialize a server config:

```bash
python -m dwlabbind.runner init --name ns1 --ip 192.0.2.10 --role master --config ./bind.xml
```

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

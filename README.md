# dwlabbind

BIND statement classes, parser, and CLI tools.

## Desired-State Contract

The reusable configuration model is documented in
[`docs/desired-state.md`](docs/desired-state.md). It defines the versioned
`dwlabbind/v1` payload used by future CLI and HTTP API operations without
coupling callers to BIND files or operating-system commands.

`BindReconciliationService` is the shared application boundary. It performs a
side-effect-free plan before delegating rendering, BIND validation, and atomic
activation to infrastructure adapters. Existing XML commands remain unchanged
until their migration to this service is complete.

## Development layout

This repository uses a `src` layout:

```text
dwlabbind/
├─ pyproject.toml
├─ src/
│  └─ dwlabbind/
├─ tests/
└─ .vscode/
```

## Local development setup

1. Create and activate a virtual environment.
2. Install in editable mode (recommended for `src` layout projects):

```bash
python -m pip install -e . --no-build-isolation
```

3. Run the CLI module:

```bash
python -m dwlabbind.runner --help
```

If you prefer running without an editable install, export `PYTHONPATH=src`.
For VS Code, copy `.env.example` to `.env`.

## CLI commands

All commands are available through `dwlabbind.runner`:

```bash
python -m dwlabbind.runner -h
```

### `desired-state-plan` and `desired-state-stage`

Plan a `dwlabbind/v1` YAML document without changing BIND:

```bash
python -m dwlabbind.runner desired-state-plan --state /etc/dwlab/dns.yaml
```

Render and validate a named release without activating it:

```bash
python -m dwlabbind.runner desired-state-stage \
  --state /etc/dwlab/dns.yaml \
  --releases-root /var/lib/dwlabbind/releases \
  --release-name 20260901-01 \
  --runtime-root /etc/bind/dwlab/current
```

The REST equivalent is `POST /desired-state/plan` with the YAML-decoded JSON
document as its request body. It returns `can_apply` and structured issues.

### `rpz`

Response policies are declarative resolver overrides. They are not an
authoritative replacement for the customer domain; unmatched names continue
through the configured recursive resolver path. Define policies in the same
desired-state YAML that is staged and activated by the deployment layer:

```yaml
response_policies:
  - name: internal-host-overrides
    zone_name: rpz.internal.dw-lab
    enabled: true
    rules:
      - query_name: t-com.dw-lab.com
        action: answer
        records:
          - type: A
            value: 192.168.2.31
```

Supported actions are `answer`, `nxdomain`, `nodata`, `passthru`, and `drop`.
`answer` supports `A`, `AAAA`, `CNAME`, and `TXT` records. The generated RPZ
zone filename is owned by dwlabbind; a customer cannot configure an arbitrary
filesystem path through this interface.

Manage rules through the same application service from the CLI:

```bash
dwlabbind rpz list --state /etc/dwlab/dns.yaml
dwlabbind rpz add --state /etc/dwlab/dns.yaml \
  --policy internal-host-overrides \
  --query-name dwlab-cmk-dev.dw-lab.com \
  --action answer --record A=192.168.2.31
dwlabbind rpz update --state /etc/dwlab/dns.yaml \
  --policy internal-host-overrides \
  --query-name dwlab-cmk-dev.dw-lab.com \
  --action nxdomain
dwlabbind rpz delete --state /etc/dwlab/dns.yaml \
  --policy internal-host-overrides \
  --query-name dwlab-cmk-dev.dw-lab.com
```

The command atomically writes only the desired-state file. Run the normal
`desired-state-stage` and deployment activation afterwards, so BIND remains
unchanged if rendering or `named-checkconf` fails.

### `legacy-xml-import`

Convert an existing `dwlabbind.xml` into a reviewable desired-state YAML file:

```bash
python -m dwlabbind.runner legacy-xml-import \
  --xml /etc/bind/dwlabbind.xml \
  --output /etc/dwlab/dns.yaml
```

The command never imports inline TSIG secrets or implicit resolver policy. Its
JSON output lists every required manual review before the new YAML is staged.

### `backup`

Back up `named.conf` plus referenced files.

```bash
python -m dwlabbind.runner backup --named-conf /etc/bind/named.conf --output /backup/named-backup.tar
```

Arguments:
- `--named-conf` (optional, default: `/etc/bind/named.conf`)
- `--output` (required, full archive path)

### `import`

Import current BIND config and write `dwlabbind.xml` next to `named.conf`.

```bash
python -m dwlabbind.runner import --named-conf /etc/bind/named.conf
```

Arguments:
- `--named-conf` (optional, default: `/etc/bind/named.conf`)

### `initialize`

Take over existing BIND layout: backup, import, write managed `dwlab` layout, validate, and activate.

```bash
python -m dwlabbind.runner initialize --named-conf /etc/bind/named.conf
```

Arguments:
- `--named-conf` (optional, default: `/etc/bind/named.conf`)
- `--xml-input` (optional, use existing `dwlabbind.xml` as initialize source model)
- `--output` (optional, backup archive path)
- `--named-etc` (optional, target config root)
- `--named-var` (optional, target zone-file root)
- `--force` (optional, recover from stale lock)
- `--nocleanup` (optional, disable legacy file cleanup after successful initialize)
- `--keep-stage-on-error` (optional, keep `/tmp/dwlabbind-stage-*` for debugging failed validation)

### `add-fixed-host`

Add one static host mapping (A/AAAA + PTR) into managed fixed-host includes.

```bash
python -m dwlabbind.runner add-fixed-host --fqdn host.example.com --ip 192.0.2.10
```

Arguments:
- `--named-conf` (optional, default: `/etc/bind/named.conf`)
- `--fqdn` (required)
- `--ip` (required)
- `--ttl` (optional)
- `--named-etc` (optional)
- `--named-var` (optional)
- `--force` (optional, overwrite conflicting mapping)

### `delete-fixed-host`

Delete static host mapping from forward/reverse zone files.

```bash
python -m dwlabbind.runner delete-fixed-host --fqdn host.example.com --ip 192.0.2.10
```

Arguments:
- `--named-conf` (optional, default: `/etc/bind/named.conf`)
- `--fqdn` (required)
- `--ip` (optional; if omitted, all A/AAAA mappings for FQDN are removed)
- `--named-etc` (optional)
- `--named-var` (optional)
- `--force` (reserved for delete policy compatibility)

### `zone-create`

Create forward + reverse zones from minimal parameters.

```bash
python -m dwlabbind.runner zone-create --domain-name example.com --dns-server 192.0.2.10/24 --base-hostname ns1
```

Arguments:
- `--named-conf` (optional, default: `/etc/bind/named.conf`)
- `--domain-name` (required)
- `--dns-server` (required, IPv4 with `/8`, `/16`, or `/24`)
- `--base-hostname` (required)
- `--named-etc` (optional)
- `--named-var` (optional)
- `--no-allow-recursion` (optional)
- `--no-allow-update` (optional)
- `--force` (optional)

### `serve-api`

Start HTTP API server.

```bash
python -m dwlabbind.runner serve-api --host 127.0.0.1 --port 8080 \
  --desired-state /etc/dwlab/dns.yaml
```

## API endpoints

When `serve-api` is running, these POST endpoints are available:

- `/backup`
- `/import`
- `/initialize`
- `/xml/load`
- `/add-fixed-host`
- `/delete-fixed-host`
- `/zone/create-minimal`
- `/zone/create`
- `/zone/update`
- `/zone/delete`

The RPZ endpoints use only the desired-state file configured when the server
starts; callers cannot supply arbitrary server-side paths:

- `GET /v1/rpz/policies`
- `GET /v1/rpz/policies/{policy}/rules`
- `POST /v1/rpz/policies/{policy}/rules`
- `PATCH /v1/rpz/policies/{policy}/rules/{query-name}`
- `DELETE /v1/rpz/policies/{policy}/rules/{query-name}`

`POST` and `PATCH` accept the JSON rule shape shown in the YAML example above.
They update desired state atomically; BIND activation remains the deployment
workflow's explicit render, validation, and release switch.

Notes:
- API mode is in-memory first: mutate server model, then sync XML.
- Writing/activating BIND files is done by initialize/write flows, not ad-hoc from UI state changes.

## XML structure for fixed hosts

Each `<zone_file>` now contains a dedicated `<fixed_hosts>` section that groups:
- include file path
- generated include statement
- fixed host entries stored in that include file

Example:

```xml
<zone_file>
  <zone_name>dw-lab.de</zone_name>
  <file_path>/var/lib/bind/dwlab/dw-lab.de.zone</file_path>
  <statements>
    ...
  </statements>
  <fixed_hosts>
    <fixed_hosts_file_path>/var/lib/bind/dwlab/dw-lab.de.zone.FixedHosts</fixed_hosts_file_path>
    <static_hosts_include>
      <include>
        <value>$INCLUDE "/var/lib/bind/dwlab/dw-lab.de.zone.FixedHosts" dw-lab.de.</value>
      </include>
      <generated>true</generated>
    </static_hosts_include>
    <entries>
      <rr>
        <value>host IN A 192.0.2.10</value>
      </rr>
      <rr>
        <value>10 IN PTR host.dw-lab.de.</value>
      </rr>
    </entries>
  </fixed_hosts>
</zone_file>
```

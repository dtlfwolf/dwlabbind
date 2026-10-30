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

### `server-listener-show` and `server-listener-update`

Define the global BIND socket bindings in desired state. This is distinct from
resolver ACLs and applies outside BIND views. The policy is intentionally
absent by default, preserving BIND's existing listener behavior until an
operator explicitly configures it.

```bash
python -m dwlabbind.runner server-listener-update \
  --state /etc/dwlab/dwlabbind/dns.yaml \
  --ipv4 127.0.0.1 \
  --ipv4 192.168.2.30
```

The command writes an explicit IPv4 policy and disables IPv6 with
`listen-on-v6 { none; };`. Add `--ipv6 ADDRESS` as required, or use `--clear`
to return to BIND's distribution defaults. As with RPZ commands, stage and
activate the resulting desired state through the normal deployment workflow.

### First Installation Modes

Installing the deployment package never changes BIND. Inspect the effective
configuration before the first activation:

```bash
dwlabbind installation-inspect --named-conf /etc/bind/named.conf
```

Select one explicit mode when activating the first release:

- `new-server`: only for a BIND server without non-default zones.
- `additive`: preserves existing DNS ownership and adds only the zones in the
  reviewed DW-Lab desired state.
- `adopt-existing`: deliberately stops. Existing-zone adoption requires the
  separate, reviewable migration workflow and is never automatic.

Validate the choice without changing BIND, then activate:

```bash
dwlabbind installation-validate \
  --named-conf /etc/bind/named.conf \
  --installation-mode additive

dwlabbind configure \
  --state /etc/dwlab/dwlabbind/dns.yaml \
  --release-name initial \
  --installation-mode additive
```

OpenVPN dynamic zone operations require a previously activated DW-Lab release.
They cannot create the first managed BIND include implicitly.

The same read-only inspection is available through the HTTP interface:

```text
GET /v1/installation
GET /v1/installation/validate/additive
```

The validation endpoint returns `409 INSTALLATION_MODE_REJECTED` for an unsafe
mode or for `adopt-existing`; neither endpoint changes BIND or desired state.

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
dwlabbind rpz policy-create --state /etc/dwlab/dns.yaml \
  --domain-name dw-lab.com
dwlabbind rpz fixed-host-add --state /etc/dwlab/dns.yaml \
  --policy dw-lab.com-overrides \
  --hostname cmkdev --ip-address 192.168.2.31
dwlabbind rpz update --state /etc/dwlab/dns.yaml \
  --policy dw-lab.com-overrides \
  --query-name cmkdev.dw-lab.com \
  --action nxdomain
dwlabbind rpz delete --state /etc/dwlab/dns.yaml \
  --policy dw-lab.com-overrides \
  --query-name cmkdev.dw-lab.com
```

`policy-create --domain-name dw-lab.com` creates the conventional state
`name: dw-lab.com-overrides` and `zone_name: rpz.dw-lab.com-overrides`.
`fixed-host-add` accepts one host label and derives the fully qualified query
name from that policy. Use the generic `rpz add` command for wildcard names or
non-`answer` actions.

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

### `legacy-migrate`

Back up the active BIND configuration, import legacy zones and TSIG file
references into desired state, validate a managed release, and activate it
transactionally:

```bash
sudo /opt/dwlab/dwlabbind/bin/dwlabbind legacy-migrate \
  --state /etc/dwlab/dwlabbind/dns.yaml \
  --release-name legacy-migration-20261016-01 \
  --backup /root/bind-before-legacy-migration.tar
```

When the active server is already managed but a preserved legacy configuration
must be re-imported, pass it separately. The active configuration is still the
configuration backed up and replaced:

```bash
sudo /opt/dwlab/dwlabbind/bin/dwlabbind legacy-migrate \
  --state /etc/dwlab/dwlabbind/dns.yaml \
  --legacy-named-conf /root/preserved-legacy-named.conf \
  --release-name corrected-legacy-migration \
  --backup /root/bind-before-corrected-migration.tar
```

Package-managed zones such as root hints are retained through the operating
system BIND configuration and are not copied into desired state. Imported zone
files are self-contained; legacy `$INCLUDE` paths are replaced by their loaded
records.

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

The fixed-host commands were renamed to `fixed-host-add` and `fixed-host-delete`
in version 0.20.15. Update scripts using the previous command names.

### `fixed-host-add`

Add one static host mapping (A/AAAA + PTR) into managed fixed-host includes.

```bash
python -m dwlabbind.runner fixed-host-add --fqdn host.example.com --ip 192.0.2.10
```

Arguments:
- `--named-conf` (optional, default: `/etc/bind/named.conf`)
- `--fqdn` (required)
- `--ip` (required)
- `--ttl` (optional)
- `--named-etc` (optional)
- `--named-var` (optional)
- `--force` (optional, overwrite conflicting mapping)

### `fixed-host-delete`

Delete static host mapping from forward/reverse zone files.

```bash
python -m dwlabbind.runner fixed-host-delete --fqdn host.example.com --ip 192.0.2.10
```

Arguments:
- `--named-conf` (optional, default: `/etc/bind/named.conf`)
- `--fqdn` (required)
- `--ip` (optional; if omitted, all A/AAAA mappings for FQDN are removed)
- `--named-etc` (optional)
- `--named-var` (optional)
- `--force` (reserved for delete policy compatibility)

### `zone-create`

Create authoritative forward + reverse zones from minimal parameters
(`--type primary`, the default).

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

To forward queries for a domain to upstream DNS servers, use `--type forward`:

```bash
dwlabbind zone-create --type forward --domain-name tcom.home.arpa \
  --forwarder 192.168.2.30 --forward-mode only
```

Repeat `--forwarder IP` for multiple upstream servers. IPv4 and IPv6 addresses
are accepted without subnet prefixes. `--forward-mode` defaults to `only`;
use `first` to allow normal recursive resolution if forwarding fails.

Forwarding zones require `--domain-name` and at least one `--forwarder`.
They create only the requested zone definition, with no new reverse zone,
zone data file, or TSIG key. `--force` replaces only the same-named zone.
The existing configuration is written through the normal managed layout writer.

For `--type forward`, `--dns-server`, `--base-hostname`, `--yaml`, `--xml`,
`--no-allow-recursion`, and `--no-allow-update` are rejected. `--forwarder`
and `--forward-mode` are accepted only with `--type forward`.

### `zone-delete`

Delete a managed zone and its linked reverse zone:

```bash
dwlabbind zone-delete --zone-name example.com
```

Use `--no-delete-related` to keep linked zones. Add `--remove-files` to
also remove the generated zone files.

### `zone-update`

Increment a zone's SOA serial and rewrite the managed configuration:

```bash
dwlabbind zone-update --zone-name example.com
```

The command names `zone-delete` and `zone-update` replace `delete-zone` and
`update-zone` starting with version 0.20.13; update existing scripts accordingly.

### `serve-api`

Start HTTP API server.

```bash
python -m dwlabbind.runner serve-api --host 127.0.0.1 --port 8080 \
  --desired-state /etc/dwlab/dns.yaml
```

For a remote controller, explicitly configure the BIND paths and a bearer
token. `serve-api` rejects a non-loopback listen address without a token.
Terminate TLS in a reverse proxy or run the API only on a trusted management
network.

```bash
python -m dwlabbind.runner serve-api --host 192.168.2.30 --port 8080 \
  --api-token "$DWLABBIND_API_TOKEN" \
  --desired-state /etc/dwlab/dwlabbind/dns.yaml \
  --releases-root /etc/bind/dwlab/releases \
  --runtime-root /etc/bind/dwlab/current \
  --named-service bind9
```

## API endpoints

When `serve-api` is running, these POST endpoints are available:

- `/backup`
- `/import`
- `/initialize`
- `/xml/load`
- `/fixed-host-add`
- `/fixed-host-delete`
- `/zone/create-minimal`
- `/zone/create`
- `/zone/update`
- `/zone/delete`

The active zone resource is separate from those legacy in-memory endpoints:

- `POST /v1/zones` creates a primary forward/reverse zone from
  `domain_name`, `dns_server_cidr`, and `base_hostname`.
- `DELETE /v1/zones/{zone-name}` removes that managed zone and related files.

Both operations invoke the same `BindRuntimeService` as `dwlabbind
ovpn-zone-ensure` and `dwlabbind ovpn-zone-remove`. They update desired state,
create or remove the TSIG key, stage and validate a release, then atomically
activate it. A bearer token is required whenever the API listens beyond
loopback.

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

The listener resource follows the same desired-state-only activation model:

- `GET /v1/server/listener`
- `PUT /v1/server/listener`
- `DELETE /v1/server/listener`

`PUT` accepts the `listener_policy` YAML object shown in the desired-state
documentation. It replaces both IP families as one validated policy.

Notes:
- The older `/zone/*` and fixed-host endpoints remain in-memory editing APIs.
- `/v1/zones` is the production resource for transactional OpenVPN zone lifecycle management.

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

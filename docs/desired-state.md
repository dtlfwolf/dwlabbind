# Desired-State Contract

## Response Policies

`response_policies` is an optional list of named BIND Response Policy Zones
(RPZ). A policy is a resolver override layer, not an authoritative zone for
the customer domain. Each policy has a generated local zone file and one or
more rules:

```yaml
response_policies:
  - name: dw-lab.com-overrides
    zone_name: rpz.dw-lab.com-overrides
    enabled: true
    rules:
      - query_name: cmkdev.dw-lab.com
        action: answer
        records:
          - type: A
            value: 192.168.2.31
```

Rules must have unique `query_name` values within a policy. Available actions:

- `answer`: return one or more `A`, `AAAA`, `CNAME`, or `TXT` records.
- `nxdomain`: return NXDOMAIN.
- `nodata`: return a successful response with no matching data.
- `passthru`: bypass the RPZ result for this name.
- `drop`: drop the query.

Only `answer` accepts records. `dwlabbind` derives its managed filename as
`rpz/<policy-name>.zone`; desired state never accepts a free-form file path.
With BIND views, dwlabbind declares every enabled policy inside every view.
The standard policy lifecycle derives `name: <domain>-overrides` and
`zone_name: rpz.<domain>-overrides` from a domain name. Its fixed-host command
then derives `<hostname>.<domain>` and selects `A` or `AAAA` from the supplied
IP address.

`dwlabbind/v1` is the transport-independent configuration contract for a BIND
server. It is the only input format future CLI, HTTP API, and reconciliation
services may use. It describes the intended DNS service; it does not expose
generated BIND files, service commands, package installation, or firewall
configuration.

The core package only validates and processes this model. A deployment package
will own operating-system provisioning and a BIND adapter will render and
activate the configuration.

## YAML Example

```yaml
schema_version: dwlabbind/v1
server:
  name: dns-01
  # Omit listener_policy to retain BIND's distribution defaults. When present,
  # it owns both address families; an empty addresses list renders "none".
  listener_policy:
    ipv4:
      addresses:
        - 127.0.0.1
        - 192.168.2.30
      port: 53
    ipv6:
      addresses: []
      port: 53
  resolver_policy:
    recursion_enabled: false
    allow_query:
      - any
    allow_recursion: []
    forwarders: []
    forward_mode: first

tsig_keys:
  - name: vpn.lab.dwlab.test
    algorithm: hmac-sha256
    secret_reference: file:///etc/bind/dwlab/keys/vpn.lab.dwlab.test.key

# Zones available without split-horizon matching.
zones: []

views:
  - name: internal
    match_clients:
      - 192.168.0.0/16
      - 10.100.0.0/16
    resolver_policy:
      recursion_enabled: true
      allow_query:
        - 192.168.0.0/16
        - 10.100.0.0/16
      allow_recursion:
        - 192.168.0.0/16
        - 10.100.0.0/16
      forwarders:
        - 1.1.1.1
      forward_mode: first
    zones:
      - name: cmk-dev.dw-lab.com
        type: primary
        file: zones/internal/cmk-dev.dw-lab.com.zone
        records:
          - "@ IN A 192.168.12.11"
      - name: vpn.lab.dwlab.test
        type: primary
        file: zones/internal/vpn.lab.dwlab.test.zone
        dynamic_update_key: vpn.lab.dwlab.test
        records: []
```

## Validation Rules

- `schema_version` must be exactly `dwlabbind/v1`.
- Views and TSIG keys have unique names, case-insensitively.
- A primary or secondary zone must have a file path relative to the managed
  BIND data root. Absolute-path policy will be enforced by the infrastructure
  renderer.
- A secondary zone declares its `primaries`; a forward zone declares its own
  `forwarders` and `forward_mode`. The model rejects incomplete zone types
  instead of relying on implicit BIND defaults.
- A dynamic primary zone must reference a declared TSIG key. Key material is
  never included: `secret_reference` points to a provisioned secret.
- Resolver recursion is explicit. Enabling it requires `allow_recursion`; it
  is never inferred from a reverse zone or client network.
- `listener_policy` is optional for backward compatibility. When configured,
  it is global to BIND, not view-specific. Each address must be a concrete IP
  address of the correct family, except for the explicit `any` opt-in. An
  empty family renders `listen-on { none; };` or `listen-on-v6 { none; };`.
- A view requires `match_clients`. BIND view order and source-match overlap
  checks will be added by the reconciliation service before configuration is
  activated.

## Boundaries

`BindDesiredState`, `View`, `Zone`, `TsigKey`, `ResolverPolicy`, and
`ListenerPolicy` are pure
domain objects. They can be constructed from a decoded YAML/JSON mapping by a
CLI command or an HTTP request. They do not read files, start BIND, invoke
`rndc`, or perform firewall changes.

## Activation Model

The renderer creates a complete release directory. Production activation will
make the BIND runtime root a stable `current` symlink to that release. Switching
the symlink is atomic; if the subsequent service reload fails, `dwlabbind`
restores the previous symlink and attempts to reload the previous release.
Release retention is a separate policy and never occurs during activation.

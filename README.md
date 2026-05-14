# Certplane

**Certplane is a small certificate control plane for servers that do not run Kubernetes.**

It helps issue and renew TLS certificates across VMs, bare metal hosts and homelab infrastructure without copying private keys between machines or distributing DNS provider credentials to every server.

## What it does

Certplane has two binaries:

| Component | Role |
|---|---|
| `broker` | Central service that authenticates agents, enforces certificate policy, talks to the configured ACME issuer, caches issued certificates and records audit events. |
| `agent` | Runs on each host, keeps private keys local, submits CSRs to the broker and installs returned certificate bundles. |

Agents authenticate to the broker with mTLS using machine identity certificates issued by an internal CA such as `step-ca`.

## Key properties

- Service private keys are generated and kept on the host that uses them.
- Certificate authorization is controlled by a declarative YAML policy.
- Designed to fit infrastructure-as-code workflows where policy and agent configs are rendered from inventory.

## Documentation

Full documentation lives at:

[certplane.kippel.org](https://certplane.kippel.org)

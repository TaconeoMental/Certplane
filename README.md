# Certplane

A lightweight control plane for certificate issuance for non-k8s
infrastructures, built around machine identity, declarative policy, and
host-local key generation.

## Agent enroll

```mermaid
sequenceDiagram
    actor Operator
    participant ICA as Internal CA
    participant Agent

    Operator->>ICA: generate bootstrap token
    ICA-->>Operator: short-lived token
    Operator->>Agent: write token to host

    Agent->>Agent: generate identity.key
    Agent->>Agent: generate CSR

    Agent->>ICA: CSR + token
    ICA-->>Agent: identity.crt
```

## Agent run
```mermaid
sequenceDiagram
    participant Agent
    participant Broker
    participant PCA as Public CA

    Agent->>Agent: generate service.key
    Agent->>Agent: generate CSR

    Agent->>Broker: mTLS(CSR + profile)
    Note over Agent,Broker: identity.crt presented as client cert

    Broker->>Broker: verify mTLS cert
    Broker->>Broker: check policy
    Broker->>Broker: validate CSR SANs

    Broker-->>Agent: cached certificate bundle (service.crt)
    Note over Broker,Agent: if requested certificate already exists

    Broker->>PCA: CSR via ACME
    PCA-->>Broker: service.crt + chain
    Broker->>Broker: cache certificate

    Broker-->>Agent: certificate bundle (service.crt)
```

# Security

Please report vulnerabilities privately to the maintainer (use GitHub's private
vulnerability reporting when enabled). Do not put credentials, real user
inventories, raw action payloads, or mailbox contents in public issues.

## Trust boundaries

- The configuration, identity-source administrative policy, credential files, and
  durable state are trusted operator inputs. Restrict filesystem and backup access.
- Source users must come from a controlled organization. Automatically provisioning
  every user of an untrusted, publicly self-registering organization is unsafe.
- The ownership mapping is authoritative. Email equality is not proof of account
  ownership. An unknown identity must never inherit another identity's mailbox.
- API credentials are powerful, even without account-destruction permission.
  Account-update permission can modify credentials through the upstream API.
  Restrict network access and credential access accordingly.
- The claim endpoint requires ZITADEL's HMAC signature, fresh timestamps, explicit
  application/organization scope, and a fresh active provisioned mapping. It is
  intended for private-network deployment, not anonymous public exposure.
- One writer per managed account/field is required. Stalwart 0.16 registry APIs do
  not provide atomic CAS. Read-before-write validation is not a distributed lock.
- Revocation has reconciliation/token/cache latency. An upstream disable is not
  an instantaneous global logout guarantee.

## Intentional safeguards

Dry-run is the default. Incomplete inventories, empty inventories (unless
explicitly allowed), collisions, wrong scopes, and bulk suspension thresholds
stop a cycle before mutations. The service does not delete mailboxes. Uncertain
creations are not blindly retried or adopted. Suspension retains mail reception
but removes interactive/API permissions. Credential material is neither fetched
from mail accounts nor synchronized from the identity provider.

Use current patched Go toolchains. CI runs race tests, vet, vulnerability scanning,
and a container build. The runtime container is non-root and has no shell.
The live-server integration test uses only a dedicated ephemeral namespace and
reserved test domain; it must never be pointed at a production mail domain.

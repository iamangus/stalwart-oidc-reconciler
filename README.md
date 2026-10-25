# stalwart-oidc-reconciler

Pre-provision and reconcile **Stalwart Community** mail accounts from an external
identity provider. Authenticate users with OIDC; reconcile their accounts through
the provider's directory API. **No Stalwart Enterprise license or SCIM endpoint
is required.**

OIDC is not a directory-enumeration protocol. This project is provider-adaptable,
not a claim that every OIDC provider exposes the same user-management API.

```text
ZITADEL API ─┐
             ├─ complete user snapshot → plan → Stalwart Community JMAP API
JSON file ───┘                           ↕
                                durable ownership state

Browser/webmail → identity provider login → access token → Stalwart
```

## Implemented

- ZITADEL organization-scoped directory adapter with bounded pagination,
  projection-sequence consistency checks, and human/machine distinction.
- Provider-neutral JSON inventory adapter and a small `identity.Source` interface
  for additional providers.
- Stalwart **0.16.x** registry adapter using `x:Account/*` and `x:Domain/get` on
  `/jmap`; the integration fixture pins **0.16.27**. Website examples using `/api`
  for registry calls do not match that release. `jmap_path` is configurable.
- `first.last@domain` allocation, Latin diacritic normalization, explicit overrides
  for collisions/unsupported names, and stable addresses after name changes.
- Pre-created accounts, display-name and disk-quota reconciliation, suspension,
  and permission-preserving reactivation.
- Dry-run by default, one-shot or continuously running, JSON logs, health,
  readiness, and Prometheus metrics.
- Optional signed **ZITADEL Actions V2 claim endpoint** linking each provisioned
  identity to its allocated mail address without changing its recovery email.
- Non-root static container, Kubernetes deployment example, unit/API tests and an
  opt-in real Community-server integration fixture.

No automatic mailbox deletion, email renaming, alias removal, administrator-role
assignment, source-password synchronization, or source-email mutation is provided.
Existing aliases, credentials, memberships, and unowned quota limits are preserved.
Lifecycle webhooks are not required: periodic full reconciliation is authoritative.
The claim endpoint is **not** a lifecycle-event/provisioning webhook.

## Quick start

Requirements: Go 1.26.10+ on Linux, a configured Stalwart domain, an identity source,
and API credentials. Linux filesystem locking enforces one process per state path.
If your distribution pins an older Go with `GOTOOLCHAIN=local`, install a patched
toolchain or prefix the build/test commands with `GOTOOLCHAIN=auto` to use Go's
verified toolchain download. The container build already pins Go 1.26.10.

```sh
make test
make vet
make build
cp examples/config.zitadel.json config.json
# Edit config.json and mount/provide the token files it references.

# Review the complete plan first. API reads only; does not save ownership state.
./bin/reconciler --config=config.json --once

# Perform one reconciliation.
./bin/reconciler --config=config.json --once --apply

# Run continuously, with the same reviewed configuration and persistent state.
./bin/reconciler --config=config.json --apply
```

`--once` emits the plan as JSON (contains identity IDs and mail addresses; treat
the output as private). Daemon logs contain counts rather than user inventories.
Every configuration field is validated; unknown fields fail startup. Supply
credentials through **files**, never URLs or committed configuration. Credential
files are re-read for each request so mounted-secret rotation does not require a
restart. Symlink-based Kubernetes Secret updates work; avoid `subPath` mounts.

### Identity mapping

`source.issuer` and `source.scope` identify an inventory. For ZITADEL, scope is the
organization ID and identity IDs are its immutable user IDs. Accounts belong to
those identities, **not** to a matching email string or display name.

For additional providers, explicitly relate the directory API ID to the OIDC
subject. A provider's API ID is not necessarily its token's `sub`, especially
with pairwise subjects. The core does not assume those are interchangeable.

Allocation examples:

- `Alice` + `Example` → `alice.example@example.com`.
- `Élodie` + `O’Connor` → `elodie.oconnor@example.com`.
- Compound words are hyphenated; missing or unsupported names require an override.
- `policy.address_overrides` maps immutable source IDs to lowercase **local
  parts**, e.g. `{"user-123": "alice.example2"}`. It does not accept full addresses.
- Overrides apply to **new** allocations. Updating an override does not rename an
  existing mailbox. Retained accounts keep their address reservations.

All humans in the scoped inventory are eligible unless explicitly excluded.
Machine identities are ignored. **Exclude break-glass identities explicitly.**
Inactive/initial users are pre-provisioned with access suspended, so they can
receive onboarding mail without obtaining interactive or API access. Active
users receive normal user roles, never mail-administration privileges.

## Safety and lifecycle behavior

1. Fetch a complete source snapshot and destination inventory **before** planning.
2. Reject incomplete/duplicate/mis-scoped snapshots, changed pagination sequences,
   excessive counts, collisions, missing owned accounts, and ownership drift.
3. Validate the entire plan before any mutation. An error blocks that cycle.
4. Save durable creation/permission-transition intent before remote mutations.
5. Commit each successful operation and retry reconciliation on later cycles.

The service **never adopts an existing account by matching an email address**.
The local ownership mapping is authoritative. Losing it does not cause automatic
adoption or mailbox deletion: existing addresses instead cause collision errors.

| Source condition | Destination behavior |
| --- | --- |
| New eligible human | Create mailbox before first login |
| Human name changes | Update display name; keep allocated address |
| Explicitly inactive/locked | Suspend access, retain account/mail and reception |
| Missing or newly excluded | Start grace timer; suspend after `missing_grace` |
| Reactivated | Restore permissions saved by this reconciler |
| Source fails or listing is incomplete | No mutations; fail readiness after stale window |
| Empty eligible inventory | Block unless `allow_empty` was explicitly enabled |

Suspension replaces effective permissions with mail-reception-only permissions and
an explicit authentication denial, so local credentials cannot bypass it. It does
not erase passwords or mail. Existing connections and token-cache invalidation
depend on Stalwart; test actual client/session revocation behavior before adopting
a strict offboarding SLA. Offline JWTs also have a bounded lifetime. End-to-end
revocation is not instantaneous just because an upstream account was disabled.

`max_suspensions` and `max_suspend_fraction` are circuit breakers. They block the
**whole cycle**, not a random subset of suspensions. The default fraction is 0.5:
disabling the only managed user is deliberately blocked. A small installation
that accepts automatic single-user suspension can explicitly configure 1.0.
No command-line switch silently bypasses the policy. Review configuration changes.

### Concurrency limitation

Stalwart 0.16 registry objects do **not** implement usable JMAP `ifInState`/CAS
semantics. Before every update this adapter re-fetches the account and refuses
stale writes, and updates only owned fields. This does not eliminate the final
server-side race window. **One reconciler and one writer for managed fields are
required.** Do not run competing controllers or edit an account during a cycle.

The file lock prevents two processes using the same local state path. Separate
state files or separate PVCs do not coordinate. Use one replica with `Recreate`,
local/durable storage, and a consistent filesystem; do not rely on unreliable NFS
locking or run active/active replicas. Kubernetes RBAC is not needed at runtime.

### State backup and uncertain writes

Back up the **state file and mail data together**. State is written atomically,
mode 0600, with file/directory fsync. It contains identity mappings and permission
backups, not source passwords, tokens, or mailbox credential hashes. Restrict
access anyway: changing state can change ownership.

A timed-out creation may have succeeded. Its entry stays `pending` and subsequent
cycles stop rather than guess ownership or create another account. To recover:

1. Stop the daemon and back up state.
2. Independently inspect the intended mailbox, audit records and its ownership.
3. If it certainly does not exist, remove only that pending entry and re-plan.
4. If it exists and ownership is independently proven, record the correct
   `account_id`/status in the pending entry, preserving its allocated address.
   Do **not** perform this migration merely because the email matches.
5. Resume with a dry run before applying. Do not hand-edit a running process's state.

An explicit single-object `notCreated` response is different: Stalwart confirmed
that no creation happened, so the reconciler releases that intent and can retry
after the underlying problem is corrected. HTTP/transport failures and malformed
or ambiguous responses never receive this treatment.

Permission transitions have separate write-ahead recovery and are resumed only
when remote permissions match either the saved original or the exact suspension
policy. Unexpected manual permission changes block reactivation rather than being
overwritten. A permanent erase of a mailbox remains an administrator action.

## ZITADEL OIDC integration

Provisioning is independent of OIDC login. Configure Stalwart's external OIDC
directory and register your portal/webmail as public ZITADEL OIDC applications
using authorization code + PKCE. On current Stalwart WebUI releases configure
the application's `oauthClientId` to ZITADEL's generated client ID.

**Community uses the global `Authentication.directoryId`.** Per-domain
`Domain.directoryId` selection is Enterprise-gated in 0.16.27, even though the
registry accepts the field. Setting only the domain field does not enable
Community OIDC. A global external directory also replaces ordinary local
password login: create and securely store an independent administrator API key
before switching, and verify it can reset the global directory during an IdP
outage. Local API keys are authenticated before the external directory. Do not
leave bootstrap recovery mode enabled as a workaround.

**Do not assume the user's ZITADEL recovery email equals its allocated mailbox.**
This matters for `first.last@domain`, external recovery emails, and stable
addresses after a name change. The optional claim handler supplies a custom
`mail_address` from the durable mapping:

1. Run the reconciler in apply mode until all intended accounts exist.
2. Create a ZITADEL Actions V2 **call** target pointing to the internal URL
   `http://reconciler:8080/hooks/zitadel/claims`. Set `interruptOnError: true`.
3. Mount that target's signing key as `signing_key_file`. Enable `zitadel_claims`
   and explicitly allow the portal/webmail client IDs.
4. Attach the target to **PreUserinfo** and **PreAccessToken** function executions.
   Preserve any existing targets when updating executions.
5. Set the Stalwart OIDC directory's `claimUsername` to `mail_address` and configure
   issuer/audience validation against the actual issued access tokens.
6. Verify authentication with real browser flows and token fixtures. Do not remove
   audience enforcement to make an incompatible client appear to work.

The handler verifies `Zitadel-Signature` HMAC in constant time, enforces timestamp
freshness, scopes users to the organization and applications, and only returns a
claim for a **fully provisioned, active** mapping. Suspended, stale, missing, and
uncertain mappings fail closed. It returns an empty claim list for unrelated
clients, making it safe to attach an instance-wide execution without modifying
other applications. No credentials, tokens, or action payloads are logged.

Mount it behind an internal Service/NetworkPolicy. It requires only read access
to state; requests do not trigger reconciliation, create accounts, or query
ZITADEL. Claims become unavailable after `max_stale` without a successful applied
cycle. Dry-run mode never serves mail claims.

Stalwart can validate JWT access tokens offline and opaque tokens through
userinfo. Test audience/scope enforcement with the **exact pinned version**;
server behavior differs between those paths. JWT access tokens with explicit
mail-resource audiences are preferable. Do not confuse ID tokens with access
tokens. Do not publish shared passwords or use an auth proxy to fake mail SSO.

## API permissions

- **ZITADEL:** a dedicated service identity able to enumerate humans and states
  in the chosen organization. Grant the narrowest available organization-scoped
  user-read role and verify its listing is complete. Avoid using an IAM_OWNER
  break-glass token as the reconciler's permanent credential.
- **Stalwart:** a dedicated API credential with `authenticate`, `sysDomainGet`,
  `sysAccountQuery`, `sysAccountGet`, `sysAccountCreate`, and `sysAccountUpdate`.
  Stalwart also requires a creator to possess the permissions it grants: use a
  dedicated empty **User** actor with its normal-user permissions plus those
  registry grants, and an API key inheriting the actor's permissions. A key
  restricted to registry operations alone cannot create normal User accounts.
  It does **not** need account destruction or impersonation (access to other
  users' mail). Normal-user grants are scoped to the dedicated actor's own empty
  mailbox. Account-update privileges are still powerful; limit network and
  secret access, and prohibit interactive use of this actor.

HTTPS is mandatory unless `allow_http` is explicitly set on that endpoint for a
trusted internal network or a loopback fixture. TLS certificate validation is
never disabled. Redirects are not followed, preventing credential forwarding.

## Container and Kubernetes

Published images: `ghcr.io/iamangus/stalwart-oidc-reconciler` (public, Linux
AMD64 and ARM64). Pushes to `main` and `v*` tags run tests, vet and vulnerability
scanning before publishing. Tags include `main`, `sha-<full commit>`, and semver
release tags; pin deployments to the published **digest**, not a moving tag.
Pull requests test code without publishing or receiving package-write access.

```sh
docker build --build-arg VERSION=0.1.0 -t stalwart-oidc-reconciler:0.1.0 .
```

The image is a static Go binary in `scratch`, includes public CA certificates,
and runs as UID/GID 65532. Provide writable persistent `/data`, read-only config,
and read-only secret mounts. No shell, cloud credentials, Kubernetes token, or
privileged container is required. See `examples/kubernetes.yaml`.

- `/healthz`: process is alive.
- `/readyz`: a successful cycle occurred within `max_stale` (including dry-run).
- `/metrics`: cycle/error/mutation counters and last successful cycle timestamp.
- `/hooks/zitadel/claims`: optional authenticated provider-specific claim adapter.

Only expose the Service internally. Protect metrics and hooks from public access.
Alert on stale reconciliation, errors, pending creations, and circuit breakers.

## Tests

```sh
go test -race ./...
go vet ./...
make scan
```

The real-server fixture requires `kubectl`, Python `requests`, and permission to
create a temporary namespace:

```sh
python3 tests/integration/kubernetes.py
```

It creates a uniquely named ephemeral namespace, starts Stalwart Community
0.16.27, bootstraps a reserved test domain, and creates a least-privilege test API
key. It verifies actual account creation/idempotence and suspension/reactivation
of a local credential, then removes the namespace. No production source users,
MX records, ingress, or mail routing are changed. Credentials are runtime-only
and are never printed. Ordinary Go tests skip this integration test by default.

The separate `TestRealZitadelSnapshot` is an opt-in **read-only** live-adapter
test. Supply `ZITADEL_INTEGRATION_ALLOW_READ=1`, `ZITADEL_TEST_ISSUER`,
`ZITADEL_TEST_ORG`, and `ZITADEL_TEST_TOKEN_FILE` to run it. It intentionally uses
one user per page to exercise real pagination and logs counts only.

## Deployment scope

This repository does not configure public MX records, an SMTP relay, webmail, DKIM,
backups for Stalwart, or third-party DNS. Those belong in the operator's deployment
repository. A mail pilot should prove webmail/OIDC and lifecycle handling before
moving real delivery. Keep identity-provider recovery independent of this mail
stack to avoid circular lockouts.

MIT licensed. Contributions adding identity adapters should normalize into
`identity.Snapshot`, preserve immutable identity IDs, and prove pagination and
failure behavior with tests. Webhooks may accelerate updates later, but must not
replace periodic reconciliation. The project is not affiliated with Stalwart or
ZITADEL.

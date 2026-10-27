# SRVD mail Keycloak provider

Pinned to **Keycloak 26.8.1**. This is a small provider, not a replacement login or
password-recovery service. The official operator can run the resulting image.

- `MailResource`: service-account/role-restricted, write-once mailbox-claim endpoint.
- `MailPasswordFactory`: exact `mail_address` lookup before the native password
  form validates credentials and enforces enabled/brute-force/MFA behavior.
- `MailResetFactory`: the same lookup before native recovery email delivery.

No invitation tokens or passwords are generated/validated by the provider. Native
Organizations invitations and native `UPDATE_EMAIL` do that. The profile/realm and
copied-flow declarations live in the infrastructure repository's auth module.
Recovery email is the built-in email; public registration remains disabled.

## Build/test

Requires JDK 21 and Maven:

```sh
mvn -B -f keycloak-provider/pom.xml verify
docker build -f keycloak-provider/Containerfile keycloak-provider
```

`test-signup.py` is a destructive test **only** for a disposable server bound to
127.0.0.1:18880, never a deployment script. Start that server with this JAR in
providers/, a temporary bootstrap administrator, /auth relative path, local dev
DB and local cache. It captures SMTP on 127.0.0.1:18025 in memory. Supply the auth
bootstrap files from the infrastructure checkout:

```sh
python3 keycloak-provider/test-signup.py \
  --plan /path/to/k8s/services/modules/auth/apps-bootstrap-chart/files \
  --keycloak-home /path/to/disposable/keycloak \
  --admin-password-file /path/to/local-test-password
```

The test reruns the CLI declarations for idempotence, signs up an invented user
through a real emailed invitation, exercises publication and mail-address
login/reset, and checks the profile. No real recipient receives mail. It does not
claim a production Stalwart inbox/SMTP test or full Matrix compatibility.

The isolated 26.8.1 browser run also verifies tampered-invitation email rejection,
ordinary-user claim/username write protection, and recovery-address change with
fresh authentication and retention of the old email until verification succeeds.
Keycloak's native verification-first signup collects the password on a subsequent
page rather than enabling the deprecated password-on-registration override.

Before production: complete MFA/lockout integration coverage; configure a dedicated SES-backed
notification path, publish/pin both images and explicitly migrate the reconciler's
admission scope. Do not enable signup just by setting registrationAllowed=true.

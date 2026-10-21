# keycloak-altcha

Keycloak authenticators that require an [ALTCHA](https://altcha.org/) proof-of-work challenge to be
solved on the login page and the forgot-password page.

- **No secret key, no outbound calls.** Keycloak issues the challenge and keeps it in the current
  authentication session. Each challenge is single use: it is removed on every check, whether the
  check passes or not.
- **No third-party service.** Only the ALTCHA browser widget (npm `altcha` 3.x) is used. The
  server-side check is implemented in this repository and has no ALTCHA server-library dependency.
- **Configurable in the admin console** (or through the Admin REST API), separately for login and
  password reset.

## Compatibility

| | |
|---|---|
| Keycloak | 26.8.x (built and integration-tested against the version in `pom.xml`) |
| Java | 21 |
| Widget | `altcha` 3.x, ALTCHA v2 challenges (`SHA-256`, uint32 counter) |

## What it provides

| Provider id | Replaces built-in step | Flow |
|---|---|---|
| `altcha-username-password-form` | Username Password Form (`auth-username-password-form`) | browser |
| `altcha-reset-credential-choose-user` | Choose User (`reset-credentials-choose-user`) | reset credentials |

Both extend the built-in classes and only add the ALTCHA check in front; everything else behaves
like the built-in step. A failed check logs an event with error `invalid_captcha` (`LOGIN_ERROR` or
`RESET_PASSWORD_ERROR`) and shows the message `altchaFailed`. A passed check adds the detail
`altcha=passed` to the event the request ends with (`LOGIN`, `LOGIN_ERROR` for a wrong password,
`SEND_RESET_PASSWORD`, ...), so captcha pass and fail counts can be read from the realm's events. A
login that finishes in a later request (OTP, required actions) does not carry the detail. A failed check is not a failed login:
it does not count towards brute-force lockout of any user, so a wrong or missing ALTCHA cannot be
used to lock an account. Passkey sign-ins (conditional WebAuthn UI) do not check a password and
skip the ALTCHA check.

## Build

```bash
mvn -B verify
# without a local JDK:
docker run --rm -u $(id -u):$(id -g) -e HOME=/tmp -v "$PWD":/w -w /w \
  maven:3.9-eclipse-temurin-21 mvn -B -Dmaven.repo.local=/w/.m2 verify
```

The jar is `target/keycloak-altcha-<version>.jar`. Released jars and their `.sha256` files are
attached to the [GitHub releases](https://github.com/allen0099/keycloak-altcha/releases).

## Install and enable

1. Copy the jar into Keycloak's `providers/` directory and restart (run `kc.sh build` first if you
   use an optimized image). Nothing changes until a flow uses the new steps. Keycloak logs
   `KC-SERVICES0047` warnings at startup; see [Upgrading](#upgrading).
2. Copy the built-in flows, swap the steps, and bind the copies to the realm. With `kcadm.sh`:

   ```bash
   REALM=myrealm
   kcadm.sh create authentication/flows/browser/copy -r "$REALM" -b '{"newName":"browser altcha"}'
   kcadm.sh create "authentication/flows/reset%20credentials/copy" -r "$REALM" \
     -b '{"newName":"reset credentials altcha"}'

   # In "browser altcha forms" (the copied forms subflow): delete auth-username-password-form,
   # add altcha-username-password-form, set it REQUIRED and raise it back to the first position.
   kcadm.sh get "authentication/flows/browser%20altcha/executions" -r "$REALM"   # find the ids
   kcadm.sh delete "authentication/executions/$OLD_ID" -r "$REALM"
   NEW_ID=$(kcadm.sh create "authentication/flows/browser%20altcha%20forms/executions/execution" \
     -r "$REALM" -s provider=altcha-username-password-form -i)
   kcadm.sh update "authentication/flows/browser%20altcha%20forms/executions" -r "$REALM" \
     -b "{\"id\":\"$NEW_ID\",\"requirement\":\"REQUIRED\"}"
   kcadm.sh create "authentication/executions/$NEW_ID/raise-priority" -r "$REALM" -b '{}'  # repeat until first

   # Same in "reset credentials altcha": replace reset-credentials-choose-user with
   # altcha-reset-credential-choose-user, REQUIRED, first position.

   kcadm.sh update "realms/$REALM" -s 'browserFlow=browser altcha' \
     -s 'resetCredentialsFlow=reset credentials altcha'
   ```

   `setup_realm()` in [`src/it/e2e.py`](src/it/e2e.py) does the same through the Admin REST API.
3. Add the widget to your login theme (see [Theme integration](#theme-integration)).

**Rollback:** bind the realm back to the built-in flows. The jar can stay installed.

```bash
kcadm.sh update "realms/$REALM" -s browserFlow=browser -s 'resetCredentialsFlow=reset credentials'
```

## Configuration

Admin console: **Authentication** → open the flow (e.g. `browser altcha`) → gear icon on the ALTCHA
step. Labels and help texts are translated (English and Traditional Chinese bundled).

| Key | Meaning | Default | Allowed |
|---|---|---|---|
| `altchaEnabled` | When `false`, no challenge is issued or checked; the step behaves like the built-in one | `true` | `true`, `false` |
| `altchaDifficulty` | Leading zero hex digits the solution needs; each step multiplies the work by 16 | `4` | `3`, `4` |
| `altchaCost` | SHA-256 iterations per attempt; work grows linearly, for fine tuning | `1` | 1–1000 |
| `altchaTtlSeconds` | How long an issued challenge stays valid | `600` | 60–3600 |

- With no config saved, the defaults apply and ALTCHA is **on**.
- Missing, unparsable or out-of-range values fall back to the default; they never break logins.
- Login and password reset have **separate** configs (each is attached to its own step).
- Settings are captured when a challenge is issued, so changing them does not break pages that are
  already open.

### Admin REST API

The settings are an ordinary authenticator config.

```bash
# The ALTCHA execution's "authenticationConfig" field holds the config id, if one was saved
kcadm.sh get "authentication/flows/browser%20altcha/executions" -r "$REALM"

# No config yet: create one
#   POST /admin/realms/{realm}/authentication/executions/{executionId}/config
kcadm.sh create "authentication/executions/$EXECUTION_ID/config" -r "$REALM" \
  -b '{"alias":"altcha-login","config":{"altchaDifficulty":"4","altchaCost":"2"}}'

# Change it. PUT replaces the whole config: keys you leave out go back to their defaults.
kcadm.sh update "authentication/config/$CONFIG_ID" -r "$REALM" -b \
  '{"id":"'"$CONFIG_ID"'","alias":"altcha-login","config":{"altchaEnabled":"true","altchaDifficulty":"4","altchaCost":"2","altchaTtlSeconds":"600"}}'
```

`kcadm.sh get ... --fields config` does not expand map values and shows the config as empty; use a
plain `get` to see it.

### Deployment automation

Administrators tune these settings in the console, so automation must not reset them:

- **Never create, overwrite or delete the ALTCHA authenticator configs** from deployment scripts.
  Rely on the built-in defaults instead.
- Install the jar, create the flows **only if they do not exist**, and bind them. Do not recreate
  an existing flow: that creates new executions and detaches the configs saved on the old ones.

## Theme integration

The jar issues and checks challenges; the login theme renders the widget.

- The challenge JSON is the template attribute **`altchaChallenge`**, set on `login.ftl` and
  `login-reset-password.ftl` only. It is **absent** when ALTCHA is disabled or the flow does not use
  these steps; render no widget then. With Keycloakify it appears in `kcContext.altchaChallenge`.
- The widget must sit inside the form and submit its payload in the field **`altcha`**:

  ```html
  <!-- FreeMarker; with a bundler: import "altcha"; -->
  <#if altchaChallenge??>
    <altcha-widget challenge="${altchaChallenge}" name="altcha" auto="onload"></altcha-widget>
  </#if>
  ```

  ```tsx
  // Keycloakify / React
  import "altcha";
  {kcContext.altchaChallenge && (
    <altcha-widget challenge={kcContext.altchaChallenge} name="altcha" auto="onload" />
  )}
  ```

- The widget uses Web Crypto, so it only works in a secure context: **HTTPS** (or `localhost`).
- Error message key: **`altchaFailed`**. English and Traditional Chinese (`zh_TW`) translations are
  bundled in the jar (`theme-resources/messages`); a theme can override them.

## Security notes

- Proof of work raises the cost of automated submissions; it does not stop a determined attacker.
  Keep Keycloak's brute-force detection on and rate-limit the login endpoints at the proxy.
- A challenge is valid once, for one authentication session, until it expires. Replaying a solved
  payload, or solving a challenge from an older page, fails. Parallel submissions of one solution
  are caught too: an accepted solution is also recorded in Keycloak's single-use object store,
  which is atomic across a cluster.

## Upgrading

- `Authenticator` is an internal Keycloak SPI, so Keycloak logs `KC-SERVICES0047` at startup, and
  these classes extend built-in ones. **Retest login and password reset on every Keycloak
  upgrade.** CI runs the end-to-end test against the Keycloak version in `pom.xml`, and Dependabot
  bumps that version.
- The challenge format is ALTCHA v2 as solved by widget 3.x. A widget major upgrade must keep
  solving v2 `SHA-256` challenges (`AltchaTest` and `src/it/e2e.py` solve exactly like the widget).

## Measured solve times

Desktop Chromium, 16 cores: difficulty 4, cost 1 takes about 0.15–0.3 s; difficulty 5 took 5–6 s,
which is why it is not offered. Phones have fewer and slower cores: measure on real devices before
raising the cost.

## Testing

- `mvn verify` runs the unit tests.
- [`src/it/e2e.py`](src/it/e2e.py) (Python 3, standard library only) drives the real login and
  forgot-password flows over HTTP, solving challenges like the widget does:

  ```bash
  docker run -d --name kc -p 127.0.0.1:8080:8080 \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
    -v "$PWD/target/keycloak-altcha-<version>.jar:/opt/keycloak/providers/keycloak-altcha.jar:ro" \
    -v "$PWD/src/it/theme/altcha-e2e:/opt/keycloak/themes/altcha-e2e:ro" \
    quay.io/keycloak/keycloak:26.8.0 start-dev
  python3 src/it/e2e.py full --base-url http://127.0.0.1:8080 --admin-user admin --admin-password admin
  ```

  `full` creates a throwaway realm (default `altcha-e2e`, refused if it exists, deleted afterwards
  unless `--keep`) with a test-only theme from `src/it/theme`. `smoke` is read-only and checks an
  existing deployment, including Keycloakify themes:

  ```bash
  python3 src/it/e2e.py smoke --base-url https://sso.example.org --realm myrealm \
    --redirect-uri https://sso.example.org/realms/myrealm/account/ \
    [--username alice --password ...] [--resolve sso.example.org:443:192.0.2.10]
  ```

## Releasing

Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
[release-please](https://github.com/googleapis/release-please) keeps a release PR open that bumps
the version in `pom.xml` and updates `CHANGELOG.md`. Merging it tags `vX.Y.Z`, creates the GitHub
release, and attaches `keycloak-altcha-X.Y.Z.jar` and its `.sha256`.

- Before 1.0.0, `feat` bumps the minor version, `fix` the patch version, and breaking changes the
  minor version.
- Release PRs are opened with `GITHUB_TOKEN`, so they do not trigger CI by themselves. They only
  change the version and changelog of a commit that already passed CI on `main`, and the release job
  runs `mvn verify` again at the tag. To run CI on the release PR anyway, start the **CI** workflow
  manually on the release-please branch.

## License

[Apache License 2.0](LICENSE)

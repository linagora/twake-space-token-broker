# twake-space-token-broker

Keeps Twake Space users' delegated tokens for their personal agents.

A personal agent never holds a credential. Its owner consents once, through their own consent link, and the broker keeps the owner's LemonLDAP refresh token, encrypted. When the agent calls a contract through APISIX, APISIX asks the broker for a fresh access token of the agent's owner, through forward-auth, and passes it on to the contract.

Twake Drive accepts only tokens of the owner's own instance, a cozy-stack. The same consent also lets the broker in on that instance, and the routes of Drive contracts get a token of it as well.

## Consent

| Request | Answer |
|---|---|
| `GET /consent?owner=<email>` | the consent link bound to its owner, as the problems below give it: a redirect to LemonLDAP |
| `GET /consent` | the plain consent link, the same for every user: a redirect to LemonLDAP |
| `GET /callback` | where LemonLDAP, then the user's Drive instance, send the user back: a short page in French |

- The consent signs the user in with the `twake-space-agents` client: an authorization code with PKCE (S256) and the scope `openid email offline_access`. The state and the PKCE verifier wait in a signed, HttpOnly cookie. The consent lasts 10 minutes, but the browser keeps the cookie an hour, so that an expired consent still starts over from the owner's link.
- A browser holds one consent at a time: opening a consent link again while one is in progress replaces it, and the first one then ends on a page saying it no longer matches the consent in progress.
- The callback checks the state, then exchanges the code with `client_secret_basic`. It stores the refresh token under the user's email, which is the `sub` of the ID token on Twake's LemonLDAP.
- The owner's link asks LemonLDAP for no new login and passes the owner as `login_hint`, so an owner already signed in consents in one go. The callback then checks that the account that signed in is the owner, exactly as the link names them, since delegations are keyed by that email. If it is not, it stores nothing, leaves that account's delegations as they were, and asks the user to open the link in a private window and sign in as the owner. That account keeps an offline session in LemonLDAP that nothing holds: LemonLDAP 2.21 cannot revoke it.
- The plain link asks for `prompt=login`, so LemonLDAP has the user sign in again when an SSO session is open, through its unstyled "Upgrade session" page. LemonLDAP's "stay connected" defeats it: its login counts as a fresh one, so a browser that remembers another account can still consent for that account unnoticed. Give users their own link.
- Consenting again replaces the stored token.
- When something fails, the page says why, with a link to start over: the owner's link again, when the consent started from it.

### Drive

- Once LemonLDAP's refresh token is stored, the callback reads the user's `workplaceFqdn` in LemonLDAP's userinfo: the host of their Drive instance. LemonLDAP must release it for the client, in JSON, under one of the scopes the broker asks for, such as `email`.
- The broker registers an OAuth client named `Assistant Twake Space` on that instance, by dynamic client registration (`POST /auth/register`), and sends the user to the instance's consent page for `io.cozy.files:GET,POST`, reading and creating files, with PKCE (S256). The client is listed among the applications connected to the instance, where the user can remove it.
- The instance sends the user back to `/callback` too, which tells the two steps apart by the signed cookie of the consent in progress. The callback checks the state, exchanges the code with the client's secret, and stores the instance's refresh token with the client.
- The user thus consents once, through the same link: they need not open anything else.
- The broker calls the host LemonLDAP names, so it accepts only an instance right under `DRIVE_INSTANCE_DOMAIN`, `<name>.<domain>`: an address, a service of the cluster or a host of another domain counts as no instance, and logs a warning. Without `DRIVE_INSTANCE_DOMAIN`, Drive is off.
- When LemonLDAP names no such instance, or cannot answer, the consent completes for LemonLDAP alone and the page says that Drive is not available. The consent never fails for Drive.
- When the user declines on their instance, or the instance fails, the page says that the agent may act for them except in Drive, and why, with the link to start over. LemonLDAP's part of the consent stays.
- Consenting again replaces the Drive delegation as well: the broker removes its earlier client from the instance, which voids that client's tokens, and Drive comes back only if the user lets the broker in again.

## Forward-auth

`GET /forward-auth` is for APISIX's `forward-auth` plugin only.

- APISIX names the agent's owner by email in the `X-Twake-User-Email` header. It must remove any value the agent sends and set the header itself, from the agent's consumer.
- On success, the broker answers 200 with `Authorization: Bearer <access token>`. List `Authorization` in the plugin's `upstream_headers`.
- A Drive route appends `?token=drive` to the plugin's URI. The broker then answers 200 with three headers: `Authorization` as above, which names the user to the contract, `X-Twake-Drive-Token`, an access token of the owner's Drive instance with no scheme, and `X-Twake-Drive-Instance`, the instance's host. List the three in the plugin's `upstream_headers`: a 200 of a Drive route always sets them, so they replace any value the agent sent. Without the query, nothing changes.
- When the owner has no Drive delegation, a Drive route asks LemonLDAP's userinfo for their instance. If LemonLDAP names one under `DRIVE_INSTANCE_DOMAIN`, the answer is `delegation_missing` with the consent link, since a new consent lets the broker in. If not, it is `drive_instance_unknown`, without the link, which would only take the owner round in circles.
- Access tokens are kept in memory and handed out for `TOKEN_REUSE_SECONDS` at most (60 seconds by default) from when the broker asked LemonLDAP for them, and never later than five minutes before they expire, then refreshed. They last 10 hours on Twake, but only a refresh shows that LemonLDAP no longer honours a delegation.
- Each refresh makes LemonLDAP look the user up and issue a new 10-hour access token, so an agent in use costs a refresh a minute by default. An outage of LemonLDAP's LDAP directory or session store longer than `TOKEN_REUSE_SECONDS` shows to agents as `delegation_expired`, where the cached token used to hide it.
- Simultaneous calls of one agent share one refresh.
- If LemonLDAP ever returns a new refresh token, it replaces the stored one.
- Drive tokens are kept and refreshed alike, under the same `TOKEN_REUSE_SECONDS`: cozy-stack's last a week, but only a refresh shows that the owner removed the broker from their instance. A Drive route asks LemonLDAP first, so a delegation LemonLDAP no longer honours gives no Drive token either. A Drive delegation the instance refuses stays stored, like LemonLDAP's, until the next consent replaces it.
- The broker deletes no delegation that LemonLDAP refuses, because LemonLDAP 2.21 answers the same errors while its LDAP directory or session store fails, and removes the offline session itself only for a user it no longer finds. A delegation thus works again after an outage without a new consent. A deleted user's row stays, and each call of their agent asks LemonLDAP again and logs a warning.

Every error is an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem (`application/problem+json`) with a stable `code`:

| Status | `code` | When |
|---|---|---|
| 400 | `missing_user_email` | the `X-Twake-User-Email` header is missing or empty |
| 400 | `unknown_token` | the `token` query asks for another token than `drive` |
| 401 | `delegation_missing` | the owner never consented, or, on a Drive route, never let the broker in on the Drive instance LemonLDAP names |
| 401 | `delegation_expired` | LemonLDAP refuses the refresh token with `invalid_request` or `invalid_grant`, such as when the user was deleted, or their offline session expired (after 30 days by default) or was revoked; or, on a Drive route, the instance refuses its refresh token, such as once the owner removed the broker from it |
| 404 | `drive_instance_unknown` | on a Drive route, the owner has no Drive delegation, and LemonLDAP names no instance under `DRIVE_INSTANCE_DOMAIN`, or that setting is unset |
| 502 | `lemonldap_unavailable` | LemonLDAP gave no usable answer, or answered another error |
| 502 | `drive_unavailable` | on a Drive route, the owner's Drive instance gave no usable answer |

- Both 401 problems carry the consent link bound to the owner in `consent_url`, for the agent to send to them.
- APISIX passes an error's status and body on to the agent. List `Content-Type` in the plugin's `client_headers` to keep `application/problem+json`.
- Routing errors, such as an unknown path, use the same format, with a `code` named after their HTTP status (`not_found`, `method_not_allowed`).

## Storage

The broker creates its tables, `delegations` and `drive_delegations`, at startup if they are missing. A row of `delegations` holds:

- the user's email;
- the refresh token, encrypted with AES-GCM and bound to that email;
- the time of its last change.

A row of `drive_delegations` holds the user's email, which refers to their row of `delegations`; the host of their Drive instance, the broker's client on it and the instance's refresh token, encrypted together the same way; and the time of its last change. Deleting a user's delegation deletes their Drive delegation with it.

The key of the tokens and the key of the consent cookie are both derived from `ENCRYPTION_KEY` with HKDF. A token that no longer decrypts, after a change of that key, counts as expired, so the next consent replaces it.

## Run

| Variable | Value |
|---|---|
| `DATABASE_URL` | the PostgreSQL database, owned by the broker's user, since the broker creates its tables |
| `OIDC_ISSUER` | LemonLDAP's issuer, such as `https://sign-up.dev.twake.lin-saas.com/` |
| `OIDC_CLIENT_ID` | `twake-space-agents` by default |
| `OIDC_CLIENT_SECRET` | the client's secret |
| `ENCRYPTION_KEY` | at least 32 random bytes, base64 encoded, such as from `openssl rand -base64 32` |
| `PUBLIC_BASE_URL` | where users reach the broker, such as `https://agent-consent.dev.twake.lin-saas.com` |
| `TOKEN_REUSE_SECONDS` | seconds an access token is handed out before LemonLDAP, or the Drive instance, is asked again, `60` by default: a revoked delegation still gets tokens for that long at most |
| `DRIVE_INSTANCE_DOMAIN` | the domain of the users' Drive instances, such as `dev.twake.lin-saas.com`: the broker lets itself in only on `<name>.<domain>`. Unset by default, which turns Drive off |

```sh
DATABASE_URL=postgresql://broker:secret@localhost:5432/broker \
OIDC_ISSUER=https://sign-up.dev.twake.lin-saas.com/ \
OIDC_CLIENT_SECRET=... ENCRYPTION_KEY=... \
PUBLIC_BASE_URL=https://agent-consent.dev.twake.lin-saas.com \
  uv run uvicorn --factory twake_space_token_broker.app:create_app_from_env --port 8080
```

The image `ghcr.io/linagora/twake-space-token-broker` listens on 8080 as user 10001 and answers the probes at `/healthz`. It logs no access lines, since the callback's query string holds the user's authorization code. It is published as `latest` from `main` and with the version from `v*` tags.

To deploy it:

- register `<PUBLIC_BASE_URL>/callback` as a redirect of the LemonLDAP client;
- publish only `/consent` and `/callback` on the public host, and let only APISIX reach `/forward-auth`;
- for Drive, set `DRIVE_INSTANCE_DOMAIN`, have LemonLDAP release `workplaceFqdn` in the client's userinfo, and let the broker reach the users' Drive instances over HTTPS;
- run a single replica, since the access tokens and the refresh lock are kept in memory.

## Test

The tests call the HTTP API against a real PostgreSQL that they start with Docker, a fake LemonLDAP and a fake cozy-stack.

```sh
uv run pytest
uv run mypy
uv run ruff check . && uv run ruff format --check .
```

## License

[AGPL-3.0](LICENSE)

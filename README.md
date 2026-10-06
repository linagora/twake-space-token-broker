# twake-space-token-broker

Keeps Twake Space users' delegated tokens for their personal agents.

A personal agent never holds a credential. Its owner consents once, through a fixed link, and the broker keeps the owner's LemonLDAP refresh token, encrypted. When the agent calls a contract through APISIX, APISIX asks the broker for a fresh access token of the agent's owner, through forward-auth, and passes it on to the contract.

## Consent

| Request | Answer |
|---|---|
| `GET /consent` | the fixed consent link, the same for every user: a redirect to LemonLDAP |
| `GET /callback` | where LemonLDAP sends the user back: a short page in French |

- The consent signs the user in with the `twake-space-agents` client: an authorization code with PKCE (S256) and the scope `openid email offline_access`. The state and the PKCE verifier wait in a signed, HttpOnly cookie for 10 minutes.
- It asks for `prompt=login`, so LemonLDAP has the user sign in again even when an SSO session is open: a browser still signed in as someone else cannot consent for them unnoticed.
- The callback checks the state, then exchanges the code with `client_secret_basic`. It stores the refresh token under the user's email, which is the `sub` of the ID token on Twake's LemonLDAP.
- Consenting again replaces the stored token.
- When something fails, the page says why, with a link to start over.

## Forward-auth

`GET /forward-auth` is for APISIX's `forward-auth` plugin only.

- APISIX names the agent's owner by email in the `X-Twake-User-Email` header. It must remove any value the agent sends and set the header itself, from the agent's consumer.
- On success, the broker answers 200 with `Authorization: Bearer <access token>`. List `Authorization` in the plugin's `upstream_headers`.
- Access tokens are kept in memory and handed out for `TOKEN_REUSE_SECONDS` at most (60 seconds by default) from when the broker asked LemonLDAP for them, and never later than five minutes before they expire, then refreshed. They last 10 hours on Twake, but only a refresh shows that LemonLDAP no longer honours a delegation.
- Each refresh makes LemonLDAP look the user up and issue a new 10-hour access token, so an agent in use costs a refresh a minute by default. An outage of LemonLDAP's LDAP directory or session store longer than `TOKEN_REUSE_SECONDS` shows to agents as `delegation_expired`, where the cached token used to hide it.
- Simultaneous calls of one agent share one refresh.
- If LemonLDAP ever returns a new refresh token, it replaces the stored one.
- The broker deletes no delegation that LemonLDAP refuses, because LemonLDAP 2.21 answers the same errors while its LDAP directory or session store fails, and removes the offline session itself only for a user it no longer finds. A delegation thus works again after an outage without a new consent. A deleted user's row stays, and each call of their agent asks LemonLDAP again and logs a warning.

Every error is an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem (`application/problem+json`) with a stable `code`:

| Status | `code` | When |
|---|---|---|
| 400 | `missing_user_email` | the `X-Twake-User-Email` header is missing or empty |
| 401 | `delegation_missing` | the owner never consented |
| 401 | `delegation_expired` | LemonLDAP refuses the refresh token with `invalid_request` or `invalid_grant`, such as when the user was deleted, or their offline session expired (after 30 days by default) or was revoked |
| 502 | `lemonldap_unavailable` | LemonLDAP gave no usable answer, or answered another error |

- Both 401 problems carry the consent link in `consent_url`, for the agent to send to its owner.
- APISIX passes an error's status and body on to the agent. List `Content-Type` in the plugin's `client_headers` to keep `application/problem+json`.
- Routing errors, such as an unknown path, use the same format, with a `code` named after their HTTP status (`not_found`, `method_not_allowed`).

## Storage

The broker creates its one table, `delegations`, at startup if it is missing. A row holds:

- the user's email;
- the refresh token, encrypted with AES-GCM and bound to that email;
- the time of its last change.

The key of the tokens and the key of the consent cookie are both derived from `ENCRYPTION_KEY` with HKDF. A token that no longer decrypts, after a change of that key, counts as expired, so the next consent replaces it.

## Run

| Variable | Value |
|---|---|
| `DATABASE_URL` | the PostgreSQL database, owned by the broker's user, since the broker creates its table |
| `OIDC_ISSUER` | LemonLDAP's issuer, such as `https://sign-up.dev.twake.lin-saas.com/` |
| `OIDC_CLIENT_ID` | `twake-space-agents` by default |
| `OIDC_CLIENT_SECRET` | the client's secret |
| `ENCRYPTION_KEY` | at least 32 random bytes, base64 encoded, such as from `openssl rand -base64 32` |
| `PUBLIC_BASE_URL` | where users reach the broker, such as `https://agent-consent.dev.twake.lin-saas.com` |
| `TOKEN_REUSE_SECONDS` | seconds an access token is handed out before LemonLDAP is asked again, `60` by default: a revoked delegation still gets tokens for that long at most |

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
- run a single replica, since the access tokens and the refresh lock are kept in memory.

## Test

The tests call the HTTP API against a real PostgreSQL that they start with Docker, and a fake LemonLDAP.

```sh
uv run pytest
uv run mypy
uv run ruff check . && uv run ruff format --check .
```

## License

[AGPL-3.0](LICENSE)

# cat4igp control room

The React 19 + TypeScript + Vite frontend is a same-origin administrator console for one standalone cat4igp server. It uses native `fetch`, MUI, cookie sessions, and no browser-held JWTs or analytics.

## Surface

The application exposes Nodes, Meshes, Invites, and Tunnels. It reads `/admin/inventory` and sends confirmed mutations to `/admin/actions` or `/admin/invites`. The frontend is limited to the local server's inventory and management actions.

The shared in-memory retry slot freezes the endpoint, JSON body, idempotency key, label, and fixed `administrator:1` subject before a mutation is sent. Network failures, timeouts, 503 responses, and unreadable responses retain the same action for explicit retry after sign-in. Definite 4xx responses end the retry. Cancel forgets the client retry but does not roll back a server commit. Reloading or closing the tab loses it.

MUI dialogs confirm destructive operations. Invite codes appear only after a successful response and are kept in transient UI state. They are never logged or persisted. The development mock uses public demo credentials and an intentionally non-Secure cookie; it is not production authentication.

## Development

From `frontend`, run `npm ci`, `npm test`, `npm run build`, and `npm run dev`. Bun equivalents work with the same scripts. The default Vite mode uses the in-memory mock API. Set `MOCK_API=0 bun run dev` or `CONTROLLER_URL=http://127.0.0.1:8080 bun run dev` to proxy a real server.

The real backend must be behind a same-origin HTTPS proxy. The proxy must preserve the browser Origin on JSON POST requests and must not expose the server's private HTTP listener. Configure the backend origin in `ADMIN_JWT_CONFIG_FILE`; do not enable credentialed CORS or weaken cookie and Origin checks.

## Production

Serve `dist/` as static files through the same HTTPS origin that proxies `/admin`. Keep the server listener private, disable caching for `/admin`, and set TLS, rate limits, body/time limits, security headers, and a restrictive CSP. The backend-issued cookie is Secure, HttpOnly, SameSite=Strict, host-only, and short-lived. There is no refresh or password-change endpoint.

The mock and browser tests cover standalone login, logout, inventory, invite management, idempotent retries, and theme preferences. Use the real server integration checks for TLS, provisioning, and database behavior.

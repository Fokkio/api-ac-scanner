# Intentionally vulnerable local fixture

This server exists only for V3.1 regression testing. Never expose it to a network.

```powershell
node server.js
```

Use `http://host.docker.internal:4100` from the scanner UI.

- Owner/expected-privileged token: `owner-local-token-1234567890`
- Alternate/lower-role token: `alternate-local-token-1234567890`
- Object path: `/api/orders/1`
- Function path: `/api/admin`
- Enumeration pair: `/api/users/alice` and `/api/users/definitely-missing`

The fixture deliberately returns the same object and admin response to both authenticated identities, and returns distinguishable existing/missing account responses.

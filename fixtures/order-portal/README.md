# Disposable Order Approval Portal

Local-only fixture for API AC Scanner V3.1. It combines a small web portal, PostgreSQL-backed users/orders/test resources, three roles, six supported authentication paths, and guarded endpoints under `/__ac_test__/`.

Demo credentials are intentionally fixed and must never be reused outside this disposable Compose profile.

| User | Password | Role |
| --- | --- | --- |
| `alice` | `alice-password` | owner |
| `bob` | `bob-password` | viewer |
| `admin` | `admin-password` | admin |

Run the full stack with `docker compose --profile demo up --build -d` and open `http://127.0.0.1:4100`.

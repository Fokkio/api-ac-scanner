# API Access-Control Scanner — convenience Makefile
# Works on Linux/macOS and Windows (Git Bash / MSYS).
# Requires: docker, docker compose v2, make.

COMPOSE = docker compose

.PHONY: help build start rebuild stop status logs open ps clean dev-web test-ssrf

help: ## Show this help
	@echo "API Access-Control Scanner — commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'
	@echo ""
	@echo "Env to set before 'start' (or edit docker-compose.yml):"
	@echo "  SESSION_SECRET  long random value (REQUIRED in prod; web refuses to start if empty)"
	@echo "  CORS_ORIGINS    comma-separated trusted origins (default http://localhost:3000)"

build: ## Build scanner + web images
	$(COMPOSE) build

start: ## Start the full stack (detached)
	$(COMPOSE) up -d

rebuild: ## Rebuild web (no-cache) + restart (after editing code)
	$(COMPOSE) build --no-cache web
	$(COMPOSE) up -d --force-recreate

stop: ## Stop and remove containers
	$(COMPOSE) down

status: ## Show container status (health)
	$(COMPOSE) ps

ps: status ## Alias for status

logs: ## Tail web + scanner logs
	$(COMPOSE) logs --tail 40 -f web scanner

open: ## Open the UI in the default browser (localhost:3000)
	@command -v xdg-open >/dev/null 2>&1 && xdg-open http://localhost:3000 || \
	command -v start >/dev/null 2>&1 && start http://localhost:3000 || \
	open http://localhost:3000 || echo "Open http://localhost:3000 manually"

clean: ## Stop + remove images/volumes created here
	$(COMPOSE) down -v --remove-orphans
	$(COMPOSE) rm -fsv

dev-web: ## Run the web UI locally (no Docker) for quick UI hacking
	cd web && npm install && npm run dev

test-ssrf: ## Run the SSRF guard + CORS unit checks inside a Python container
	docker run --rm -v "$$(pwd)/scanner/app:/app/app" -w /app python:3.11-slim \
		bash -c "pip install -q httpx fastapi 2>/dev/null; \
		python - <<'PY'
from app import engines
tests = [
    ('http://127.0.0.1:8000/api', True),
    ('http://localhost:3000', True),
    ('http://169.254.169.254/latest/meta-data/', True),
    ('http://10.0.0.5:6379/', True),
    ('http://192.168.1.1/', True),
    ('http://[::1]/x', True),
    ('http://8.8.8.8/', False),
    ('http://example.com/', False),
    ('https://api.github.com/', False),
]
ok = sum(1 for u,e in tests if engines.is_blocked_target(u)==e)
for u,e in tests:
    print(f'  [{\"PASS\" if engines.is_blocked_target(u)==e else \"FAIL\"}] expect={e} {u}')
print(f'SSRF: {ok}/{len(tests)} passed')
PY"

#!/bin/sh
set -eu

# 1. Schema migrations + restricted runtime role, as the schema owner.
#    Same path locally (docker compose) and on AWS RDS - see scripts/bootstrap_db.py.
DB_USER="${ADMIN_DB_USER:-cyberdesk}" DB_PASS="$ADMIN_DB_PASS" python scripts/bootstrap_db.py

# 2. Serve web traffic as the restricted runtime user only; drop the owner password.
export DB_USER="${APP_DB_USER:-cyberdesk_app}"
export DB_PASS="$APP_DB_PASS"
unset ADMIN_DB_PASS

exec "$@"

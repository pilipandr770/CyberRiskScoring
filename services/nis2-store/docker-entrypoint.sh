#!/bin/sh
set -e

echo "Waiting for database..."
python -c "
import time, os
import psycopg2
url = os.environ.get('DATABASE_URL') or os.environ.get('LOCAL_DATABASE_URL')
for i in range(30):
    try:
        psycopg2.connect(url).close()
        print('DB is up')
        break
    except Exception as exc:
        print(f'DB not ready yet ({exc}), retrying...')
        time.sleep(2)
else:
    raise SystemExit('Database never became available')
"

echo "Running migrations..."
flask db upgrade

exec "$@"

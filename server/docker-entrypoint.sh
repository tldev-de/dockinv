#!/bin/sh

if [ "$DATABASE_AUTO_UPGRADE" = 1 ]; then
  echo "Running migrations ..."
  flask db upgrade
fi

exec "$@"
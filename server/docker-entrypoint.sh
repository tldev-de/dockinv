#!/bin/sh

if [ "$DATABASE_AUTO_UPGRADE" = 1 ]; then
  echo "Running migrations ..."
  flask db upgrade
fi

if [ "$HOSTS_ADD_DEV_AGENT" = 1 ]; then
  echo "add dev agent ..."
  flask hosts add agent --address http://agent:9999/ --token your_secret
fi

exec "$@"
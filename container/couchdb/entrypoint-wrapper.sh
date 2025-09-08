#!/bin/bash
set -e

# This script will wait for CouchDB to be fully initialized, then
# apply a custom configuration and restart the service.

# Directory where user's custom INI files are mounted
CONFIG_SOURCE_DIR="/tmp/configs"
# CouchDB's actual config directory
CONFIG_TARGET_DIR="/opt/couchdb/etc/local.d"

# 1. Check if the database has already been initialized by looking for the users database file.
#    On subsequent runs, this allows us to skip the waiting process.
if [ ! -f /opt/couchdb/data/_users.couch ]; then
    echo "First run detected. Initializing CouchDB..."

    # Start the original entrypoint script in the background
    # This will create the admin user and system databases
    /docker-entrypoint.sh /opt/couchdb/bin/couchdb &
    COUCHDB_PID=$!

    # Wait for the server to be responsive and for the _users database to be created
    echo "Waiting for initialization to complete..."
    until curl -sf -o /dev/null "http://${COUCHDB_USER}:${COUCHDB_PASSWORD}@127.0.0.1:5984/_users"; do
        echo "CouchDB not ready, waiting 5 seconds..."
        sleep 5
    done
    echo "Initialization complete."

    # Stop the temporary CouchDB process
    echo "Stopping temporary CouchDB instance."
    kill "${COUCHDB_PID}"
    wait "${COUCHDB_PID}" || true
fi

# 2. Copy the final, restrictive configuration into place.
#    This will run on the first start (after initialization) and all subsequent starts.
echo "Applying final configuration from ${CONFIG_SOURCE_DIR}"
cp -v "${CONFIG_SOURCE_DIR}"/*.ini "${CONFIG_TARGET_DIR}"/

# 3. Start CouchDB in the foreground with the final configuration.
#    The 'exec' command replaces this script with the CouchDB process,
#    ensuring it correctly receives signals from Docker.
echo "Starting CouchDB with final configuration..."
exec /docker-entrypoint.sh /opt/couchdb/bin/couchdb

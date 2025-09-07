FROM couchdb:3.5

COPY ./local.ini /opt/couchdb/etc/local.d/local.ini
RUN chown couchdb:couchdb /opt/couchdb/etc/local.d/local.ini

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
COPY ./entrypoint-wrapper.sh /usr/local/bin/entrypoint-wrapper.sh
RUN chmod +x /usr/local/bin/entrypoint-wrapper.sh

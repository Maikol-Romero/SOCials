FROM supabase/postgres:15.14.1.095

USER root

RUN apk add --no-cache python3 py3-pip curl &&     pip3 install --break-system-packages patroni[etcd]==4.0.4 psycopg2-binary &&     rm -rf /var/cache/apk/*

RUN mkdir -p /etc/patroni && chown postgres:postgres /etc/patroni

USER postgres

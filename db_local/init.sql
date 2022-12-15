CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    balance INT8
);

CREATE TABLE transfers (
    id UUID PRIMARY KEY,
    source UUID,
    destination UUID,
    amount INT8,
    ts TIMESTAMP DEFAULT now()
);

CREATE TABLE anomalies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source UUID,
    destination UUID,
    reason STRING
) WITH (ttl_expire_after = '1 minutes', ttl_job_cron = '*/1 * * * *');

SET cluster setting kv.rangefeed.enabled = true;

/*
SQL Function
CREATE FUNCTION isFraud(source UUID, destination UUID) RETURNS INT IMMUTABLE LEAKPROOF LANGUAGE SQL AS 'SELECT COUNT(1) FROM transfers WHERE source = $1 AND destination = $2 having count(1) > 4';

CDC
CREATE CHANGEFEED INTO "http://localhost:8000/" WITH schema_change_policy = 'stop' AS SELECT source, destination FROM transfers;

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
    transfer_id UUID,
    anomaly_level STRING
) WITH (ttl_expire_after = '1 minutes', ttl_job_cron = '*/1 * * * *');

CREATE TABLE blocked_accounts (
    source UUID PRIMARY KEY,
    reason STRING
) WITH (ttl_expire_after = '10 minutes', ttl_job_cron = '*/10 * * * *');

SET cluster setting kv.rangefeed.enabled = true;


-- SQL Function
-- CREATE FUNCTION anomalyLevel(id UUID) RETURNS STRING IMMUTABLE LEAKPROOF LANGUAGE SQL AS '
-- SELECT
--     CASE
--         WHEN amount < 500 THEN ''Ok''
--         WHEN amount < 1000 THEN ''Warning''
--         ELSE ''Alert''
--     END
-- FROM transfers
-- WHERE id = $1
-- ';

-- -- CDC
-- CREATE CHANGEFEED INTO "http://localhost:8000/" 
--     WITH schema_change_policy = 'stop' AS 
--     SELECT id, source, destination FROM transfers WHERE amount > 100;

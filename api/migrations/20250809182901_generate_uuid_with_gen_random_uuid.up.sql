CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE organisations
    ALTER COLUMN uuid TYPE UUID USING uuid::UUID,
    ALTER COLUMN uuid SET DEFAULT gen_random_uuid();

ALTER TABLE organisation_domains
    ALTER COLUMN uuid TYPE UUID USING uuid::UUID,
    ALTER COLUMN uuid SET DEFAULT gen_random_uuid();

ALTER TABLE roles
    ALTER COLUMN uuid TYPE UUID USING uuid::UUID,
    ALTER COLUMN uuid SET DEFAULT gen_random_uuid();

ALTER TABLE permissions
    ALTER COLUMN uuid TYPE UUID USING uuid::UUID,
    ALTER COLUMN uuid SET DEFAULT gen_random_uuid();

ALTER TABLE users
    ALTER COLUMN uuid TYPE UUID USING uuid::UUID,
    ALTER COLUMN uuid SET DEFAULT gen_random_uuid();
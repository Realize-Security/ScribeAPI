-- Drop functions
DROP FUNCTION IF EXISTS validate_role_permission();
DROP FUNCTION IF EXISTS validate_user_role_assignment();
DROP FUNCTION IF EXISTS update_timestamp();

-- Drop tables in reverse order to handle dependencies
DROP TABLE IF EXISTS user_roles CASCADE;
DROP TABLE IF EXISTS role_permissions CASCADE;
DROP TABLE IF EXISTS bad_users CASCADE;
DROP TABLE IF EXISTS user_organisations CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS organisation_permissions CASCADE;
DROP TABLE IF EXISTS organisation_roles CASCADE;
DROP TABLE IF EXISTS permissions CASCADE;
DROP TABLE IF EXISTS roles CASCADE;
DROP TABLE IF EXISTS organisation_invites CASCADE;
DROP TABLE IF EXISTS organisation_domains CASCADE;
DROP TABLE IF EXISTS organisations CASCADE;

-- Drop extension
DROP EXTENSION IF EXISTS pgcrypto;
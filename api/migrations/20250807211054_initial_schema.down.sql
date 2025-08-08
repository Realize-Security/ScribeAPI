DROP INDEX IF EXISTS idx_permissions_permission_name;
DROP INDEX IF EXISTS idx_roles_role_name;
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_organisation_domains_domain;

DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS organisation_domains;
DROP TABLE IF EXISTS organisations;
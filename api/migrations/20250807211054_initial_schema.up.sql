-- Extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =========================================
-- Organisations
-- =========================================
CREATE TABLE IF NOT EXISTS organisations (
                                             id BIGSERIAL PRIMARY KEY,
                                             uuid UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
                                             name VARCHAR(255) NOT NULL,
                                             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                             updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                             deleted_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_organisations_id ON organisations(id);

-- =========================================
-- Organisation Domains
-- =========================================
CREATE TABLE IF NOT EXISTS organisation_domains (
                                                    id BIGSERIAL PRIMARY KEY,
                                                    uuid UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
                                                    domain VARCHAR(255) NOT NULL,
                                                    organisation_id BIGINT NOT NULL,
                                                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                    deleted_at TIMESTAMP,
                                                    FOREIGN KEY (organisation_id) REFERENCES organisations(id) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_organisation_domains_domain ON organisation_domains(domain);
CREATE INDEX IF NOT EXISTS idx_organisation_domains_organisation_id ON organisation_domains(organisation_id);

-- =========================================
-- Organisation Invites
-- =========================================
CREATE TABLE IF NOT EXISTS organisation_invites (
                                                    id BIGSERIAL PRIMARY KEY,
                                                    uuid UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
                                                    organisation_id BIGINT NOT NULL,
                                                    invite_token UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
                                                    expires_at TIMESTAMP NOT NULL,
                                                    email VARCHAR(255) NOT NULL,
                                                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                    deleted_at TIMESTAMP,
                                                    FOREIGN KEY (organisation_id) REFERENCES organisations(id) ON UPDATE CASCADE ON DELETE CASCADE,
                                                    CHECK (expires_at > CURRENT_TIMESTAMP)
);
CREATE INDEX IF NOT EXISTS idx_organisation_invites_organisation_id ON organisation_invites(organisation_id);

-- =========================================
-- Roles
-- =========================================
CREATE TABLE IF NOT EXISTS roles (
                                     id BIGSERIAL PRIMARY KEY,
                                     uuid UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
                                     role_name VARCHAR(255) NOT NULL,
                                     description VARCHAR(500),
                                     default_role BOOLEAN DEFAULT FALSE,
                                     organisation_id BIGINT,
                                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                     updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                     deleted_at TIMESTAMP,
                                     FOREIGN KEY (organisation_id) REFERENCES organisations(id) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_roles_role_name ON roles(role_name);
CREATE INDEX IF NOT EXISTS idx_roles_organisation_id ON roles(organisation_id);

-- Partial unique index to ignore soft deletes
CREATE UNIQUE INDEX uniq_roles_role_name_org_active
    ON roles (role_name, organisation_id)
    WHERE deleted_at IS NULL;

-- =========================================
-- Permissions
-- =========================================
CREATE TABLE IF NOT EXISTS permissions (
                                           id BIGSERIAL PRIMARY KEY,
                                           uuid UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
                                           permission_name VARCHAR(255) NOT NULL,
                                           default_permission BOOLEAN DEFAULT FALSE,
                                           organisation_id BIGINT,
                                           created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                           updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                           deleted_at TIMESTAMP,
                                           FOREIGN KEY (organisation_id) REFERENCES organisations(id) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_permissions_permission_name ON permissions(permission_name);
CREATE INDEX IF NOT EXISTS idx_permissions_organisation_id ON permissions(organisation_id);

-- Partial unique index to ignore soft deletes
CREATE UNIQUE INDEX uniq_permissions_perm_name_org_active
    ON permissions (permission_name, organisation_id)
    WHERE deleted_at IS NULL;

-- =========================================
-- Organisation Roles
-- =========================================
CREATE TABLE IF NOT EXISTS organisation_roles (
                                                  id BIGSERIAL PRIMARY KEY,
                                                  uuid UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
                                                  organisation_id BIGINT NOT NULL,
                                                  role_id BIGINT NOT NULL,
                                                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                  deleted_at TIMESTAMP,
                                                  FOREIGN KEY (organisation_id) REFERENCES organisations(id) ON UPDATE CASCADE ON DELETE CASCADE,
                                                  FOREIGN KEY (role_id) REFERENCES roles(id) ON UPDATE CASCADE ON DELETE CASCADE,
                                                  UNIQUE (organisation_id, role_id)
);
CREATE INDEX IF NOT EXISTS idx_organisation_roles_organisation_id ON organisation_roles(organisation_id);
CREATE INDEX IF NOT EXISTS idx_organisation_roles_role_id ON organisation_roles(role_id);

-- =========================================
-- Organisation Permissions
-- =========================================
CREATE TABLE IF NOT EXISTS organisation_permissions (
                                                        id BIGSERIAL PRIMARY KEY,
                                                        uuid UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
                                                        organisation_id BIGINT NOT NULL,
                                                        permission_id BIGINT NOT NULL,
                                                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                        deleted_at TIMESTAMP,
                                                        FOREIGN KEY (organisation_id) REFERENCES organisations(id) ON UPDATE CASCADE ON DELETE CASCADE,
                                                        FOREIGN KEY (permission_id) REFERENCES permissions(id) ON UPDATE CASCADE ON DELETE CASCADE,
                                                        UNIQUE (organisation_id, permission_id)
);
CREATE INDEX IF NOT EXISTS idx_organisation_permissions_organisation_id ON organisation_permissions(organisation_id);
CREATE INDEX IF NOT EXISTS idx_organisation_permissions_permission_id ON organisation_permissions(permission_id);

-- =========================================
-- Users
-- =========================================
CREATE TABLE IF NOT EXISTS users (
                                     id BIGSERIAL PRIMARY KEY,
                                     uuid UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
                                     first_name VARCHAR(255) NOT NULL,
                                     last_name VARCHAR(255) NOT NULL,
                                     email VARCHAR(255) NOT NULL,
                                     password TEXT NOT NULL,
                                     is_active BOOLEAN DEFAULT TRUE,
                                     terms_accepted BOOLEAN DEFAULT FALSE,
                                     password_reset_token VARCHAR(255) UNIQUE,
                                     password_reset_expires_at TIMESTAMP,
                                     last_login_at TIMESTAMP,
                                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                     updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                     deleted_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_id ON users(id);

-- Partial unique index to ignore soft deletes
CREATE UNIQUE INDEX uniq_users_email_active
    ON users (email)
    WHERE deleted_at IS NULL;

-- =========================================
-- User Organisations
-- =========================================
CREATE TABLE IF NOT EXISTS user_organisations (
                                                  id BIGSERIAL PRIMARY KEY,
                                                  user_id BIGINT NOT NULL,
                                                  organisation_id BIGINT NOT NULL,
                                                  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                  left_at TIMESTAMP,
                                                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                  FOREIGN KEY (user_id) REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE,
                                                  FOREIGN KEY (organisation_id) REFERENCES organisations(id) ON UPDATE CASCADE ON DELETE CASCADE,
                                                  UNIQUE(user_id, organisation_id)
);
CREATE INDEX IF NOT EXISTS idx_user_organisations_user_id ON user_organisations(user_id);
CREATE INDEX IF NOT EXISTS idx_user_organisations_organisation_id ON user_organisations(organisation_id);

-- =========================================
-- Bad Users
-- =========================================
CREATE TABLE IF NOT EXISTS bad_users (
                                         id BIGSERIAL PRIMARY KEY,
                                         uuid UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
                                         email VARCHAR(255) NOT NULL,
                                         bad_user_reason VARCHAR(500) DEFAULT '',
                                         organisation_id BIGINT,
                                         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                         updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                         deleted_at TIMESTAMP,
                                         FOREIGN KEY (organisation_id) REFERENCES organisations(id) ON UPDATE CASCADE ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_bad_users_organisation_id ON bad_users(organisation_id);

-- =========================================
-- Role Permissions
-- =========================================
CREATE TABLE IF NOT EXISTS role_permissions (
                                                role_id BIGINT NOT NULL,
                                                permission_id BIGINT NOT NULL,
                                                PRIMARY KEY (role_id, permission_id),
                                                FOREIGN KEY (role_id) REFERENCES roles(id) ON UPDATE CASCADE ON DELETE CASCADE,
                                                FOREIGN KEY (permission_id) REFERENCES permissions(id) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);

-- =========================================
-- User Roles
-- =========================================
CREATE TABLE IF NOT EXISTS user_roles (
                                          id BIGSERIAL PRIMARY KEY,
                                          user_id BIGINT NOT NULL,
                                          organisation_id BIGINT NOT NULL,
                                          role_id BIGINT NOT NULL,
                                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                          deleted_at TIMESTAMP,
                                          FOREIGN KEY (user_id) REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE,
                                          FOREIGN KEY (organisation_id) REFERENCES organisations(id) ON UPDATE CASCADE ON DELETE CASCADE,
                                          FOREIGN KEY (role_id) REFERENCES roles(id) ON UPDATE CASCADE ON DELETE CASCADE,
                                          UNIQUE (user_id, organisation_id, role_id)
);
CREATE INDEX IF NOT EXISTS idx_user_roles_organisation_id ON user_roles(organisation_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);

-- =========================================
-- Triggers & Functions
-- =========================================

-- Update updated_at
CREATE OR REPLACE FUNCTION update_timestamp() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Attach update_timestamp trigger to all relevant tables
CREATE TRIGGER trg_organisations_update
    BEFORE UPDATE ON organisations
    FOR EACH ROW EXECUTE PROCEDURE update_timestamp();

CREATE TRIGGER trg_organisation_domains_update
    BEFORE UPDATE ON organisation_domains
    FOR EACH ROW EXECUTE PROCEDURE update_timestamp();

CREATE TRIGGER trg_organisation_invites_update
    BEFORE UPDATE ON organisation_invites
    FOR EACH ROW EXECUTE PROCEDURE update_timestamp();

CREATE TRIGGER trg_roles_update
    BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE PROCEDURE update_timestamp();

CREATE TRIGGER trg_permissions_update
    BEFORE UPDATE ON permissions
    FOR EACH ROW EXECUTE PROCEDURE update_timestamp();

CREATE TRIGGER trg_organisation_roles_update
    BEFORE UPDATE ON organisation_roles
    FOR EACH ROW EXECUTE PROCEDURE update_timestamp();

CREATE TRIGGER trg_organisation_permissions_update
    BEFORE UPDATE ON organisation_permissions
    FOR EACH ROW EXECUTE PROCEDURE update_timestamp();

CREATE TRIGGER trg_users_update
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE PROCEDURE update_timestamp();

CREATE TRIGGER trg_user_organisations_update
    BEFORE UPDATE ON user_organisations
    FOR EACH ROW EXECUTE PROCEDURE update_timestamp();

CREATE TRIGGER trg_bad_users_update
    BEFORE UPDATE ON bad_users
    FOR EACH ROW EXECUTE PROCEDURE update_timestamp();

CREATE TRIGGER trg_user_roles_update
    BEFORE UPDATE ON user_roles
    FOR EACH ROW EXECUTE PROCEDURE update_timestamp();

-- Validate that the role exists for the org or is global + linked
CREATE OR REPLACE FUNCTION validate_user_role_assignment() RETURNS TRIGGER AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM roles r
        WHERE r.id = NEW.role_id
          AND (
            r.organisation_id = NEW.organisation_id
                OR (
                r.organisation_id IS NULL
                    AND EXISTS (
                    SELECT 1
                    FROM organisation_roles orl
                    WHERE orl.role_id = r.id
                      AND orl.organisation_id = NEW.organisation_id
                )
                )
            )
    ) THEN
        RAISE EXCEPTION 'Role % not available for organisation %',
            NEW.role_id, NEW.organisation_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_user_roles_insert
    BEFORE INSERT OR UPDATE ON user_roles
    FOR EACH ROW EXECUTE PROCEDURE validate_user_role_assignment();


CREATE OR REPLACE FUNCTION validate_role_permission() RETURNS TRIGGER AS $$
BEGIN
    -- Permission must be global OR match the role's organisation
    IF NOT EXISTS (
        SELECT 1
        FROM permissions p
        WHERE p.id = NEW.permission_id
          AND (
            p.organisation_id IS NULL
                OR p.organisation_id = (
                SELECT organisation_id
                FROM roles
                WHERE id = NEW.role_id
            )
            )
    ) THEN
        RAISE EXCEPTION 'Permission % not available for role %',
            NEW.permission_id, NEW.role_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_role_permissions_insert
    BEFORE INSERT OR UPDATE ON role_permissions
    FOR EACH ROW
EXECUTE FUNCTION validate_role_permission();

-- Add CHECK constraints to make organisation_id required unless default is true
ALTER TABLE permissions
    ADD CONSTRAINT check_org_id_if_not_default_perm
        CHECK (default_permission OR organisation_id IS NOT NULL);

ALTER TABLE roles
    ADD CONSTRAINT check_org_id_if_not_default_role
        CHECK (default_role OR organisation_id IS NOT NULL);
-- =========================================================================
-- V1__init_schema.sql - Migration Flyway initiale PassBanned (PostgreSQL)
-- Protège la base contre l'écrasement à chaque redéploiement
-- =========================================================================

-- 1. Table des utilisateurs du système (agents et administrateurs)
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(120) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'USER',
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    avatar_url VARCHAR(255),
    last_login TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_configured BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    flyasky_sub VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_flyasky_sub ON users(flyasky_sub);

-- 2. Table des passagers interdits de vol (Blacklist sûreté aérienne)
CREATE TABLE IF NOT EXISTS banned_passengers (
    id BIGSERIAL PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100),
    phone VARCHAR(20),
    passport_number VARCHAR(20) NOT NULL UNIQUE,
    nationality VARCHAR(50) NOT NULL,
    date_of_birth DATE NOT NULL,
    ban_reason VARCHAR(1000) NOT NULL,
    ban_date DATE NOT NULL,
    ban_duration VARCHAR(20) NOT NULL DEFAULT 'TEMPORARY',
    ban_end_date DATE,
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    notes TEXT,
    image_url VARCHAR(500),
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    created_by_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_banned_passengers_passport ON banned_passengers(passport_number);
CREATE INDEX IF NOT EXISTS idx_banned_passengers_status ON banned_passengers(status);
CREATE INDEX IF NOT EXISTS idx_banned_passengers_severity ON banned_passengers(severity);
CREATE INDEX IF NOT EXISTS idx_banned_passengers_ban_date ON banned_passengers(ban_date);

-- 3. Table des journaux d'audit et de traçabilité (Audit Logs)
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    category VARCHAR(50),
    description VARCHAR(500) NOT NULL,
    user_email VARCHAR(100),
    user_name VARCHAR(100),
    user_role VARCHAR(50),
    target_resource VARCHAR(150),
    status VARCHAR(30) DEFAULT 'SUCCESS',
    ip_address VARCHAR(45),
    details TEXT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_user_email ON audit_logs(user_email);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_logs(category);


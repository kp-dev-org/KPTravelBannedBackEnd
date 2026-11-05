ALTER TABLE users
DROP CONSTRAINT users_role_check;

ALTER TABLE users
    ADD CONSTRAINT users_role_check
        CHECK (role IN ('USER', 'ADMIN', 'SUPER_ADMIN'));

-- Modifier le rôle de l'administrateur Asky
UPDATE users
SET role = 'SUPER_ADMIN'
WHERE LOWER(email) = 'eabi@flyasky.com';

ALTER TABLE banned_passengers
    ADD COLUMN IF NOT EXISTS passport_expiry_date DATE,
    ADD COLUMN IF NOT EXISTS passport_issuing_country VARCHAR(100);

CREATE INDEX IF NOT EXISTS idx_banned_passengers_passport_expiry ON banned_passengers(passport_expiry_date);

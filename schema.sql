CREATE TABLE IF NOT EXISTS links (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(80) UNIQUE NOT NULL,
    label VARCHAR(70) NOT NULL,
    created TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS visits (
    id BIGSERIAL PRIMARY KEY,
    link_id BIGINT NOT NULL REFERENCES links(id) ON DELETE CASCADE,
    visited TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    city VARCHAR(160),
    region VARCHAR(160),
    country VARCHAR(160),
    country_code VARCHAR(8),
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    timezone VARCHAR(160),
    network VARCHAR(160)
);

CREATE INDEX IF NOT EXISTS visits_link_id_idx ON visits(link_id);

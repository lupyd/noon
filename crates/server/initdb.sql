


CREATE TABLE IF NOT EXISTS keys (
    id SERIAL NOT NULL PRIMARY KEY,
    rsa_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS forms (
    id BIGSERIAL NOT NULL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    owner VARCHAR NOT NULL,
    fields JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_forms_owner ON forms(owner);

CREATE TABLE IF NOT EXISTS form_allowed_participants (
    form_id BIGINT NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    participant VARCHAR NOT NULL,
    accepted BOOLEAN DEFAULT FALSE,

    PRIMARY KEY (form_id, participant)
);


CREATE TABLE IF NOT EXISTS form_submissions (
    form_id BIGINT NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

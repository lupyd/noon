


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
    fields BYTEA NOT NULL,
    mentioned_emails TEXT[] DEFAULT '{}',
    deadline TIMESTAMPTZ
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
    data BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS otp_codes (
    id BIGSERIAL NOT NULL PRIMARY KEY,
    email VARCHAR NOT NULL,
    code VARCHAR NOT NULL,
    form_id BIGINT REFERENCES forms(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN DEFAULT FALSE
);

-- Ensure form_id is nullable if the table already exists
ALTER TABLE otp_codes ALTER COLUMN form_id DROP NOT NULL;

CREATE INDEX IF NOT EXISTS idx_otp_codes_form_email ON otp_codes(form_id, email);
CREATE INDEX IF NOT EXISTS idx_otp_codes_expires ON otp_codes(expires_at) WHERE used = FALSE;
 
 
 CREATE TABLE IF NOT EXISTS secrets (
     id SERIAL PRIMARY KEY,
     key_data BYTEA NOT NULL,
     created_at TIMESTAMPTZ DEFAULT NOW(),
     expires_at TIMESTAMPTZ
 );

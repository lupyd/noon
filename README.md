# Noon

![Noon Logo](assets/noon.webp)

Anonymous form suite powered by blind signature cryptography.

## Overview

Noon is a privacy-preserving form submission system that enables anonymous responses while maintaining authenticity verification. Built with Rust and React.

## Key Features

- **Blind Signature Cryptography**: RSA-based blind signing allows anonymous form submissions with cryptographic proof of authenticity
- **Multiple Field Types**: TEXT, TEXTAREA, NUMBER, SELECT, MULTI_SELECT, RADIO, CHECKBOX, DATE, TIME, EMAIL, URL
- **Dual Submission Modes**: Authenticated with email or anonymous blind signature submissions
- **Access Control**: Form creators can restrict submissions to allowed participants

## Architecture

```
noon/
├── crates/
│   ├── core/          # Blind signature cryptography library
│   └── server/        # Hyper + Tokio HTTP API server
└── frontend/          # React 19 + TypeScript frontend
```

### Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Rust (async) |
| Server | Hyper + Tokio |
| Frontend | React 19 + TypeScript + Vite |
| Database | PostgreSQL |
| Auth | Email OTP Verification |
| Serialization | Protocol Buffers |

## Quick Start

### Prerequisites

- Rust toolchain
- PostgreSQL database
- Node.js (for frontend)

### Backend

```bash
# Configure environment
export DB_CONN_STR=postgres://user:pass@host:port/database
export PORT=39210

# Build and run
cargo build --release
cargo run -p noon-server
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## Configuration

### Backend (Rust)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DB_CONN_STR` | **Yes** | - | PostgreSQL connection string |
| `DB_POOL_SIZE` | No | `100` | Database connection pool size |
| `DB_CERT` | No | - | Path to SSL certificate for DB |
| `PORT` | No | `39210` | API server port |
| `RUST_LOG` | No | `info` | Logging level (`debug`, `info`, `warn`, `error`) |
| `AUTH_ISS` | No | `noon.lupyd.com` | JWT Issuer for email authentication |
| `AUTH_AUD` | No | `noon-api` | JWT Audience for email authentication |
| `FRONTEND_URL` | No | `http://localhost:8080` | Base URL of the frontend (used in emails) |
| `MAX_PARTICIPANTS` | No | `10` | Maximum participants per form |
| `SKIP_EMAIL_SENDING` | No | `false` | If `true`, emails are logged to console instead of sent |
| `SMTP_HOST` | No* | - | SMTP server address (Required if `SKIP_EMAIL_SENDING=false`) |
| `SMTP_USERNAME` | No* | - | SMTP username (Required if `SKIP_EMAIL_SENDING=false`) |
| `SMTP_PASSWORD` | No* | - | SMTP password (Required if `SKIP_EMAIL_SENDING=false`) |
| `SMTP_FROM` | No* | - | "From" email address (Required if `SKIP_EMAIL_SENDING=false`) |
| `SMTP_POOL_SIZE` | No | `4` | Number of concurrent email workers |
| `EMULATOR_MODE` | No | `false` | Enable testing features |

### Frontend (Vite)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VITE_NOON_API_URL` | **Yes** | `http://localhost:39210` | Backend API URL |
| `VITE_MAX_PARTICIPANTS`| No | `10` | UI limit for participant list |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/forms/create` | Create a new form |
| `GET` | `/forms/:id` | Get form by ID |
| `GET` | `/forms/:id/public_key` | Get RSA public key |
| `POST` | `/forms/:id/submit` | Submit form (authenticated) |
| `POST` | `/forms/:id/blind_sign` | Request blind signature |
| `POST` | `/forms/:id/submit_blind` | Submit anonymously |
| `GET` | `/health` | Health check |

## Blind Signature Flow

1. **Identity Verification**: Client authenticates via Email OTP to receive a short-lived token.
2. **Blinding**: Client generates a secret message and blinds it with the server's public key.
3. **Authorized Signing**: Server signs the blinded message only if the client has a valid token (without seeing the content).
4. **Unblinding**: Client unblinds the signature to get a valid RSA signature for the original message.
5. **Anonymous Submission**: Client submits the form response and the unblinded signature via an unauthenticated request.
6. **Verification**: Server verifies the signature using its public key, ensuring authenticity while remaining "blind" to the submitter's identity.

For a deep dive into the cryptography and anonymity guarantees, click [here](https://blogs.lupyd.com/blog/introducing-noon-anonymous-form-submissions).

## Anonymity Considerations

While Noon uses strong cryptography, true anonymity in a web environment is challenging due to network-level linkability (IP addresses) and browser fingerprinting. For maximum privacy, we recommend:
- Using different network paths for the signing and submission steps (e.g., submitting via Tor).
- Avoiding browser-based submissions for extremely sensitive data.

## License

MIT

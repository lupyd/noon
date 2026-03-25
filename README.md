# Noon

Anonymous form suite powered by blind signature cryptography.

## Overview

Noon is a privacy-preserving form submission system that enables anonymous responses while maintaining authenticity verification. Built with Rust and React.

## Key Features

- **Blind Signature Cryptography**: RSA-based blind signing allows anonymous form submissions with cryptographic proof of authenticity
- **Multiple Field Types**: TEXT, TEXTAREA, NUMBER, SELECT, MULTI_SELECT, RADIO, CHECKBOX, DATE, TIME, EMAIL, URL
- **Dual Submission Modes**: Standard authenticated or anonymous blind signature submissions
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
| Auth | Auth0 JWT |
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

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DB_CONN_STR` | Yes | - | PostgreSQL connection string |
| `AUTHZERO_ISSUER` | No | `https://lupyd.com/` | Auth0 issuer URL |
| `AUTHZERO_DOMAIN` | No | `lupyd.com` | Auth0 domain |
| `AUTHZERO_AUDIENCE` | No | `https://lupyd.com` | Auth0 audience |
| `PORT` | No | `39210` | Server port |
| `EMULATOR_MODE` | No | `false` | Enable emulator features |
| `NO_TOKEN_VERIFICATION` | No | `false` | Skip JWT verification (dev only) |

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

1. Client blinds form data with server's public key
2. Server signs blind data without seeing content
3. Client unblinds signature
4. Client submits form with unblinded signature
5. Server verifies signature without learning submission content

## License

MIT

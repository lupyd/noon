use bun, pnpm

if DB schema requires changes, update initdb.sql only at the end of file with # migrations comment and reason

this is live in production, so any changes has to reflect preserving existing base and logic

## Form Participant Modes
- **LIST_OF_EMAILS (0)**: Whitelisted email verification. Only emails specified by the owner can participate.
- **ANY_WITH_EMAIL (1)**: Open to any email verification. Respondents enter their email, verify via OTP, and submit anonymously.
- **NO_EMAIL_REQUIRED (2)**: Open guest submissions. No email is collected or verified. Uses browser guest token (`Guest <uuid>`) for double-submission prevention and cap checks.

## Participant Caps & Limits
- Forms can set a `participant_cap` which is enforced at both signing and submission endpoints.
- Cap is checked against `form_allowed_participants` active count and `form_submissions` total rows.

## Custom Reply Emails
- Pro/Team tier form creators can set a `submission_reply_message` (up to 250 characters).
- Sent via a decoupled `POST /forms/:id/send_reply` endpoint to maintain submission anonymity.
- Rate-limited to exactly 1 email per participant per form, tracked using raw emails in `form_reply_log`.
- Also displayed directly on the submission success page.


## Database Query Conventions

For enhanced type safety and to minimize network round trips (which can break transactional pooling), **NEVER** use the regular `query`, `execute`, `query_one`, or `query_option` methods. Instead, always use their "typed" counterparts:

-   **`query_typed`**: Instead of `query`
-   **`query_typed_one`**: Instead of `query_one`
-   **`execute_typed`**: Instead of `execute`
-   **`query_typed_option`**: Instead of `query_option`

These methods are specifically designed for this project to ensure parameter types are explicitly handled and performance is optimized for transactional pooling.


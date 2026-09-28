# Business Exception Detector V42

A production-oriented full-stack MVP built from V41.

## Included
- Express server/API
- SQLite persistence
- Account creation and login
- HTTP-only session cookie using JWT
- Per-user workspace
- CSV upload with server-side scanning
- Duplicate detection
- Payment exception detection
- Persistent exception records
- Resolve/ignore workflow
- Scan history
- Searchable dashboard

## Run locally
1. Install Node.js 20+.
2. Run `npm install`.
3. Copy `.env.example` to `.env` and set a long random `JWT_SECRET`.
4. Run `npm start`.
5. Open `http://localhost:3000`.

## Important production hardening
Before accepting real customer accounting data:
- Use HTTPS.
- Put the database on encrypted persistent storage.
- Replace the fallback JWT secret.
- Add rate limiting and CSRF protection.
- Add secure password hashing such as Argon2/bcrypt rather than the demo SHA-256 helper.
- Add email verification/password reset.
- Add workspace membership/roles.
- Add automated backups and retention/deletion policies.
- Add malware/file-content validation and stricter CSV limits.
- Add Stripe only after pricing/customer validation.
- Add XLSX ingestion and accounting-platform connectors after the CSV workflow is proven.

This build is a working production-oriented MVP, not a claim that those security/deployment steps are already complete.

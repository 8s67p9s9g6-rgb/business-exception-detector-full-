# Render deployment

1. Create a new GitHub repository.
2. Upload this project. Do not upload `.env`, `.sqlite`, or real customer data.
3. In Render, create a Web Service from that GitHub repository.
4. The included `render.yaml` supplies the Node build/start commands, a generated JWT secret,
   and a persistent disk for the SQLite database.
5. Deploy and open the HTTPS URL Render gives you.
6. Create a test account and upload the supplied synthetic CSV.

Before real customer financial data, add stronger password hashing, rate limiting,
password reset/email verification, upload validation, monitoring/backups, retention/deletion
controls, and a proper production database if the pilot grows.

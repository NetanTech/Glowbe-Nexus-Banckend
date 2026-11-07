# Glowbe Nexus Backend

Node.js + Express + TypeScript API, structured like Bidoro backend.

## Setup

```bash
cd C:\Users\ERROR\Documents\CODE\glowbe-nexus-backend
cp .env.example .env
npm install
```

Fill Neon `DATABASE_URL` and `JWT_SECRET` in `.env`, then apply the schema.

```bash
npm run db:migrate
```

```bash
npm run dev
```

API: `http://localhost:3003`

## Auth routes

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/register` | Create account + send OTP |
| POST | `/api/auth/login` | Login |
| POST | `/api/auth/verify-email` | Verify OTP |
| POST | `/api/auth/resend-verification` | Resend OTP |
| POST | `/api/auth/forgot-password` | Send reset OTP |
| POST | `/api/auth/reset-password` | Set new password |
| POST | `/api/auth/refresh` | Refresh access token |
| GET | `/api/auth/me` | Current user |

Response shape matches Bidoro: `{ success, message, data }`.

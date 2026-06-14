# DealMaker API

Cloudflare Workers + D1 backend for DealMaker authentication.

## Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/api/auth/challenge` | Get signed challenge key | — |
| POST | `/api/auth/setup` | Create first admin (one-time) | — |
| POST | `/api/auth/login` | Login (requires challenge key) | Challenge |
| POST | `/api/auth/register` | Register (requires challenge key) | Challenge |
| GET | `/api/auth/me` | Get current user | JWT |
| POST | `/api/auth/admin/keys` | Generate registration keys | Admin JWT |
| GET | `/api/auth/admin/keys/stats` | Key usage stats | Admin JWT |

## Deploy

```bash
npx wrangler deploy
```

Set secrets:

```bash
npx wrangler secret put JWT_SECRET
```

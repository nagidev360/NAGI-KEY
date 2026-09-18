# NAGI KEY

Production licensing API for NAGI applications.

## Render
Build command:
`npm install`

Start command:
`npm start`

Required environment variables:
- DATABASE_URL
- ADMIN_EMAIL
- ADMIN_PASSWORD
- JWT_SECRET
- LICENSE_SIGNING_SECRET
- NODE_ENV=production
- CORS_ORIGINS
- PORT (Render may provide this automatically)

Health:
GET /health
GET /api/health

Admin:
POST /api/v1/admin/login
POST /api/v1/admin/logout
GET /api/v1/admin/licenses
POST /api/v1/admin/licenses
GET /api/v1/admin/licenses/:id
POST /api/v1/admin/licenses/:id/revoke
POST /api/v1/admin/licenses/:id/suspend
POST /api/v1/admin/licenses/:id/reactivate
POST /api/v1/admin/licenses/:id/extend
GET /api/v1/admin/licenses/:id/activations
POST /api/v1/admin/activations/:id/deactivate

Client:
POST /api/v1/license/activate
POST /api/v1/license/verify
POST /api/v1/license/deactivate

The service automatically creates the required schema and registers SANTHOSH_BARCODE_GEN on first successful database connection. Production schema changes should be migrated rather than destructively resetting tables.

Never commit real secrets.

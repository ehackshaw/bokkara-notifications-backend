# Bokkara Notifications Backend

Vercel Node.js API starter for Shopify connectivity checks. The folder layout fixes the prior import error: `lib/shopify.js` is at the repository root, **not** inside `api`.

## API routes

- `GET /api/health` — public health check.
- `POST /api/test-shopify` — protected Shopify connection check; requires `x-internal-secret` header.

## Vercel environment variables

Set `SHOPIFY_STORE_DOMAIN` (actual `.myshopify.com` domain), `SHOPIFY_CLIENT_ID`, `SHOPIFY_CLIENT_SECRET`, and `INTERNAL_API_SECRET` in Vercel project settings. Never commit real values. Redeploy after updating variables.

## Current scope

This starter tests Shopify Admin API access only. It does **not** yet verify a signed-in customer, check membership status, register devices, or send Firebase notifications. Those features require additional authenticated backend endpoints and Firebase service credentials. Shopify client-credentials access depends on the app/store installation supporting that grant.

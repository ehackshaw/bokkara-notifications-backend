const SHOPIFY_API_VERSION = '2026-10';

export async function getShopifyAccessToken() {
  const shop = process.env.SHOPIFY_STORE_DOMAIN;
  const clientId = process.env.SHOPIFY_CLIENT_ID;
  const clientSecret = process.env.SHOPIFY_CLIENT_SECRET;

  if (!shop || !clientId || !clientSecret) {
    throw new Error('Missing Shopify configuration');
  }

  const domain = shop.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/.test(domain)) {
    throw new Error('Invalid Shopify store domain');
  }

  const response = await fetch(`https://${domain}/admin/oauth/access_token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: clientId,
      client_secret: clientSecret
    }),
    signal: AbortSignal.timeout(10000)
  });

  if (!response.ok) {
    throw new Error(`Shopify authentication failed (HTTP ${response.status})`);
  }

  const data = await response.json();
  if (!data.access_token) throw new Error('Shopify returned no access token');
  return { shop: domain, accessToken: data.access_token };
}

export async function shopifyGraphQL(query, variables = {}) {
  const { shop, accessToken } = await getShopifyAccessToken();
  const response = await fetch(`https://${shop}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Shopify-Access-Token': accessToken
    },
    body: JSON.stringify({ query, variables }),
    signal: AbortSignal.timeout(10000)
  });

  if (!response.ok) throw new Error(`Shopify API request failed (HTTP ${response.status})`);
  const result = await response.json();
  if (result.errors?.length) throw new Error('Shopify GraphQL request failed');
  return result.data;
}

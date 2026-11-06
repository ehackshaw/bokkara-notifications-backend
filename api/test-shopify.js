
import { getShopifyAccessToken, shopifyGraphQL } from "../lib/shopify.js";

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({
      success: false,
      error: "Method not allowed"
    });
  }

  const configuredSecret = process.env.INTERNAL_API_SECRET;
  const suppliedSecret = req.headers["x-internal-secret"];

  if (
    !configuredSecret ||
    typeof suppliedSecret !== "string" ||
    suppliedSecret !== configuredSecret
  ) {
    return res.status(401).json({
      success: false,
      error: "Unauthorized"
    });
  }

  try {
    await getShopifyAccessToken();

    const data = await shopifyGraphQL(`
      query {
        shop {
          name
        }
      }
    `);

    if (!data?.shop?.name) {
      throw new Error("Shopify returned no shop information");
    }

    return res.status(200).json({
      success: true,
      service: "Bokkara Notifications",
      shopify: "connected",
      message: "Shopify authentication and Admin API access verified"
    });

  } catch (error) {
    console.error("Shopify connection test failed:", error.message);

    return res.status(502).json({
      success: false,
      shopify: "connection_failed",
      message: "Shopify connection could not be verified"
    });
  }
}


import { createHmac, timingSafeEqual } from "node:crypto";
import { shopifyGraphQL } from "../lib/shopify.js";

function verifyShopifySignature(params) {
  const secret = process.env.SHOPIFY_CLIENT_SECRET;
  const signature = params.get("signature");

  if (!secret || !signature || !/^[a-f0-9]{64}$/i.test(signature)) {
    return false;
  }

  const entries = [...params.entries()]
    .filter(([key]) => key !== "signature")
    .sort(([a], [b]) => a.localeCompare(b));

  const message = entries
    .map(([key, value]) => `${key}=${value}`)
    .join("");

  const expected = createHmac("sha256", secret)
    .update(message)
    .digest("hex");

  return timingSafeEqual(
    Buffer.from(expected, "hex"),
    Buffer.from(signature, "hex")
  );
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({
      success: false,
      error: "Method not allowed"
    });
  }

  try {
    const url = new URL(req.url, "https://localhost");
    const params = url.searchParams;

    if (!verifyShopifySignature(params)) {
      return res.status(401).json({
        success: false,
        error: "Invalid Shopify proxy signature"
      });
    }

    const configuredShop = process.env.SHOPIFY_STORE_DOMAIN
      ?.replace(/^https?:\/\//, "")
      .replace(/\/.*$/, "")
      .toLowerCase();

    if (
      !configuredShop ||
      params.get("shop")?.toLowerCase() !== configuredShop
    ) {
      return res.status(403).json({
        success: false,
        error: "Shop not authorized"
      });
    }

    const customerId = params.get("logged_in_customer_id");

    if (!customerId || !/^\d+$/.test(customerId)) {
      return res.status(200).json({
        success: true,
        authenticated: false,
        notificationEligibility: "none"
      });
    }

    const data = await shopifyGraphQL(`
      query VerifyNotificationCustomer($id: ID!) {
        customer(id: $id) {
          id
          membershipNumber: metafield(
            namespace: "custom"
            key: "membership_number"
          ) {
            value
          }
        }
      }
    `, {
      id: `gid://shopify/Customer/${customerId}`
    });

    if (!data?.customer) {
      return res.status(403).json({
        success: false,
        error: "Customer not found"
      });
    }

    const hasMembershipNumber =
      typeof data.customer.membershipNumber?.value === "string" &&
      data.customer.membershipNumber.value.trim().length > 0;

    return res.status(200).json({
      success: true,
      authenticated: true,
      notificationEligibility: hasMembershipNumber
        ? "member"
        : "membership_invitation"
    });

  } catch (error) {
    console.error("Shopify proxy verification failed:", error.message);

    return res.status(502).json({
      success: false,
      error: "Unable to verify customer notification eligibility"
    });
  }
}

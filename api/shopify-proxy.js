import {
  createHmac,
  randomBytes,
  createHash,
  timingSafeEqual,
  createPublicKey
} from "node:crypto";

import { shopifyGraphQL } from "../lib/shopify.js";
import { getBokkaraFirestore } from "../lib/firebase.js";

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

function hashValue(value) {
  return createHash("sha256").update(value).digest("hex");
}

function validatePublicKey(encodedKey) {
  if (
    typeof encodedKey !== "string" ||
    encodedKey.length < 100 ||
    encodedKey.length > 3000
  ) {
    return null;
  }

  try {
    const key = createPublicKey({
      key: Buffer.from(encodedKey, "base64"),
      format: "der",
      type: "spki"
    });

    if (
      key.asymmetricKeyType !== "ec" ||
      key.asymmetricKeyDetails?.namedCurve !== "prime256v1"
    ) {
      return null;
    }

    return key.export({
      format: "der",
      type: "spki"
    }).toString("base64");
  } catch {
    return null;
  }
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

    // Reject stale signed proxy requests to limit replay of account identity.
    const timestamp = params.get("timestamp");
    const timestampSeconds = Number(timestamp);
    if (!timestamp || !/^\d{10,}$/.test(timestamp) || !Number.isSafeInteger(timestampSeconds) ||
        Math.abs(Date.now() - timestampSeconds * 1000) > 5 * 60 * 1000) {
      return res.status(401).json({ success: false, error: "Expired Shopify proxy request" });
    }

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

    const action = params.get("action");
    if (action && action !== "registration_challenge") {
      return res.status(400).json({ success: false, error: "Unsupported action" });
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

    const eligibility = hasMembershipNumber
      ? "member"
      : "membership_invitation";

    if (action === "registration_challenge") {
      const publicKey = validatePublicKey(
        params.get("device_public_key")
      );

      if (!publicKey) {
        return res.status(400).json({
          success: false,
          error: "A valid device public key is required"
        });
      }

      const challenge = randomBytes(32).toString("hex");
      const now = Date.now();

      await getBokkaraFirestore()
        .collection("registration_challenges")
        .doc(hashValue(challenge))
        .set({
          customerId: data.customer.id,
          publicKey,
          // Snapshot of Shopify membership eligibility for the authenticated
          // registration attempt. This is not a push trigger by itself.
          notificationEligibility: eligibility,
          createdAt: now,
          expiresAt: now + 60000,
          used: false
        });

      return res.status(200).json({
        success: true,
        authenticated: true,
        customerId: data.customer.id,
        notificationEligibility: eligibility,
        registrationChallenge: challenge,
        expiresInSeconds: 60
      });
    }

    return res.status(200).json({
      success: true,
      authenticated: true,
      customerId: data.customer.id,
      notificationEligibility: eligibility
    });

  } catch (error) {
    console.error(
      "Shopify proxy request failed:",
      error.message
    );

    return res.status(502).json({
      success: false,
      error: "Unable to process Shopify customer verification"
    });
  }
}


import { timingSafeEqual } from "node:crypto";
import { shopifyGraphQL } from "../lib/shopify.js";

function isAuthorized(req) {
  const expected = process.env.INTERNAL_API_SECRET;
  const provided = req.headers["x-internal-secret"];

  if (
    !expected ||
    typeof provided !== "string" ||
    provided.length !== expected.length
  ) {
    return false;
  }

  return timingSafeEqual(
    Buffer.from(provided),
    Buffer.from(expected)
  );
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");

    return res.status(405).json({
      success: false,
      error: "Method not allowed"
    });
  }

  if (!isAuthorized(req)) {
    return res.status(401).json({
      success: false,
      error: "Unauthorized"
    });
  }

  try {
    const data = await shopifyGraphQL(`
      query {
        customers(first: 10) {
          edges {
            node {
              id
              membershipNumber: metafield(
                namespace: "custom"
                key: "membership_number"
              ) {
                value
              }
            }
          }
        }
      }
    `);

    const customers = data?.customers?.edges ?? [];

    const members = customers.filter(
      ({ node }) =>
        typeof node.membershipNumber?.value === "string" &&
        node.membershipNumber.value.trim().length > 0
    ).length;

    return res.status(200).json({
      success: true,
      shopify: "connected",
      metafield: "custom.membership_number",
      customersChecked: customers.length,
      customersWithMembershipNumber: members,
      customersWithoutMembershipNumber: customers.length - members,
      note: "Verification sample only. No customer information returned."
    });

  } catch (error) {
    console.error("Membership test failed:", error.message);

    return res.status(502).json({
      success: false,
      error: "Membership verification failed"
    });
  }
}

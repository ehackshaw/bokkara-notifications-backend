
import { getBokkaraFirestore } from "../lib/firebase.js";

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
  const providedSecret = req.headers["x-internal-secret"];

  if (
    !configuredSecret ||
    typeof providedSecret !== "string" ||
    providedSecret !== configuredSecret
  ) {
    return res.status(401).json({
      success: false,
      error: "Unauthorized"
    });
  }

  try {
    const db = getBokkaraFirestore();

    // Test Firestore connectivity without writing customer data.
    await db.collection("_connection_test").limit(1).get();

    return res.status(200).json({
      success: true,
      firebase: "connected",
      firestore: "connected",
      message: "Bokkara Notifications Firebase connection verified."
    });
  } catch (error) {
    console.error("Firebase connection test failed:", error.message);

    return res.status(500).json({
      success: false,
      firebase: "connection_failed",
      error: "Unable to connect to Cloud Firestore."
    });
  }
}

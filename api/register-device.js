import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { getBokkaraFirestore } from "../lib/firebase.js";

const sha256 = value => createHash("sha256").update(value).digest("hex");
const validChallenge = value => typeof value === "string" && /^[a-f0-9]{64}$/i.test(value);
const validSignature = value => typeof value === "string" && value.length > 0 && value.length <= 512 && /^[A-Za-z0-9+/]+={0,2}$/.test(value);
const validFcmToken = value => typeof value === "string" && value.length >= 30 && value.length <= 4096 && /^[A-Za-z0-9:_-]+$/.test(value);

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ success: false, error: "Method not allowed" });
  }

  const { challenge, signature, fcmToken, platform } = req.body || {};
  if (!validChallenge(challenge) || !validSignature(signature) || !validFcmToken(fcmToken) || platform !== "android") {
    return res.status(400).json({ success: false, error: "Invalid registration request" });
  }

  // PRE-LAUNCH TEST MODE ONLY. A signed challenge proves key possession, NOT
  // that the request originated from the authentic Bokkara Android app.
  // Fail closed unless an explicit customer allowlist is configured.
  const allowedCustomers = new Set(
    (process.env.BOKKARA_TEST_CUSTOMER_IDS || "")
      .split(",").map(value => value.trim()).filter(Boolean)
  );
  if (allowedCustomers.size === 0) {
    return res.status(503).json({ success: false, error: "Device registration not enabled" });
  }

  try {
    const db = getBokkaraFirestore();
    const challengeRef = db.collection("registration_challenges").doc(sha256(challenge));
    const deviceRef = db.collection("notification_devices").doc(sha256(fcmToken));
    const now = Date.now();
    const result = await db.runTransaction(async transaction => {
      const [challengeSnapshot, deviceSnapshot] = await Promise.all([
        transaction.get(challengeRef), transaction.get(deviceRef)
      ]);
      if (!challengeSnapshot.exists) return { status: 401, error: "Challenge not found" };
      const record = challengeSnapshot.data();
      if (record.used !== false || typeof record.expiresAt !== "number" || now >= record.expiresAt) {
        return { status: 401, error: "Challenge expired or already used" };
      }
      if (typeof record.customerId !== "string" || !/^gid:\/\/shopify\/Customer\/\d+$/.test(record.customerId) || typeof record.publicKey !== "string") {
        return { status: 401, error: "Invalid challenge record" };
      }
      if (!allowedCustomers.has(record.customerId)) {
        return { status: 403, error: "Account not enabled for notification testing" };
      }
      let verified = false;
      try {
        const key = createPublicKey({ key: Buffer.from(record.publicKey, "base64"), format: "der", type: "spki" });
        verified = key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1" &&
          verifySignature("sha256", Buffer.from(challenge, "utf8"), key, Buffer.from(signature, "base64"));
      } catch { verified = false; }
      if (!verified) return { status: 401, error: "Device signature verification failed" };

      // Never allow an existing token to silently switch customer accounts.
      const previous = deviceSnapshot.exists ? deviceSnapshot.data() : null;
      if (previous && previous.customerId !== record.customerId) {
        return { status: 409, error: "Device token already associated with another account" };
      }
      transaction.update(challengeRef, { used: true, usedAt: now });
      transaction.set(deviceRef, {
        customerId: record.customerId,
        fcmToken,
        tokenHash: sha256(fcmToken),
        publicKeyHash: sha256(record.publicKey),
        platform: "android",
        active: true,
        createdAt: previous?.createdAt || now,
        updatedAt: now,
        testRegistration: true
      });
      return { status: 200 };
    });
    if (result.status !== 200) return res.status(result.status).json({ success: false, error: result.error });
    return res.status(200).json({ success: true, challengeVerified: true, deviceRegistered: true, testRegistration: true });
  } catch (error) {
    console.error("Device registration failed:", error.message);
    return res.status(500).json({ success: false, error: "Unable to register device" });
  }
}

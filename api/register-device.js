
import {
  createHash,
  createPublicKey,
  verify as verifySignature
} from "node:crypto";

import { getBokkaraFirestore } from "../lib/firebase.js";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function isValidChallenge(value) {
  return typeof value === "string" &&
    /^[a-f0-9]{64}$/i.test(value);
}

function isValidBase64(value) {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= 512 &&
    /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({
      success: false,
      error: "Method not allowed"
    });
  }

  const { challenge, signature } = req.body || {};

  if (
    !isValidChallenge(challenge) ||
    !isValidBase64(signature)
  ) {
    return res.status(400).json({
      success: false,
      error: "Invalid registration request"
    });
  }

  try {
    const db = getBokkaraFirestore();
    const challengeRef = db
      .collection("registration_challenges")
      .doc(sha256(challenge));

    const result = await db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(challengeRef);

      if (!snapshot.exists) {
        return { status: 401, error: "Challenge not found" };
      }

      const record = snapshot.data();

      if (
        record.used !== false ||
        typeof record.expiresAt !== "number" ||
        Date.now() >= record.expiresAt
      ) {
        return {
          status: 401,
          error: "Challenge expired or already used"
        };
      }

      if (
        typeof record.customerId !== "string" ||
        typeof record.publicKey !== "string"
      ) {
        return {
          status: 401,
          error: "Invalid challenge record"
        };
      }

      let verified = false;

      try {
        const publicKey = createPublicKey({
          key: Buffer.from(record.publicKey, "base64"),
          format: "der",
          type: "spki"
        });

        verified = verifySignature(
          "sha256",
          Buffer.from(challenge, "utf8"),
          publicKey,
          Buffer.from(signature, "base64")
        );
      } catch {
        verified = false;
      }

      if (!verified) {
        return {
          status: 401,
          error: "Device signature verification failed"
        };
      }

      transaction.update(challengeRef, {
        used: true,
        usedAt: Date.now()
      });

      return { status: 200 };
    });

    if (result.status !== 200) {
      return res.status(result.status).json({
        success: false,
        error: result.error
      });
    }

    return res.status(200).json({
      success: true,
      challengeVerified: true,
      deviceRegistered: false,
      message: "Device proof verified. Registration is not yet enabled."
    });

  } catch (error) {
    console.error(
      "Device registration verification failed:",
      error.message
    );

    return res.status(500).json({
      success: false,
      error: "Unable to verify device registration"
    });
  }
}

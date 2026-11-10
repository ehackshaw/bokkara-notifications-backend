import { GoogleAuth } from 'google-auth-library';
import { createHash } from 'node:crypto';

const PLAY_INTEGRITY_SCOPE = 'https://www.googleapis.com/auth/playintegrity';
const sha256base64url = value => createHash('sha256').update(value).digest('base64url');

// Must match Android's Standard Integrity requestHash construction exactly.
export function registrationRequestHash(challenge, fcmToken, publicKey) {
  return sha256base64url(`bokkara-register-v1\n${challenge}\n${fcmToken}\n${publicKey}`);
}

function getGoogleAuth() {
  const email = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY;

  // Vercel often stores PEM newlines as literal backslash-n sequences.
  if (email && privateKey) {
    return new GoogleAuth({
      credentials: {
        client_email: email,
        private_key: privateKey.replace(/\\n/g, '\n'),
      },
      scopes: [PLAY_INTEGRITY_SCOPE],
    });
  }

  // Allow Application Default Credentials in environments that support them.
  return new GoogleAuth({ scopes: [PLAY_INTEGRITY_SCOPE] });
}

export async function verifyAndroidIntegrity(integrityToken, expectedRequestHash) {
  if (typeof integrityToken !== 'string' || integrityToken.length < 20 || integrityToken.length > 20000) return false;
  const packageName = process.env.BOKKARA_ANDROID_PACKAGE_NAME || 'com.bokkara.app';
  const client = await getGoogleAuth().getClient();
  const url = `https://playintegrity.googleapis.com/v1/${encodeURIComponent(packageName)}:decodeIntegrityToken`;
  const response = await client.request({
    url,
    method: 'POST',
    data: { integrity_token: integrityToken },
  });

  const payload = response.data?.tokenPayloadExternal;
  const request = payload?.requestDetails;
  const app = payload?.appIntegrity;
  const device = payload?.deviceIntegrity;
  const ts = Number(request?.timestampMillis);

  const valid = request?.requestPackageName === packageName &&
    request?.requestHash === expectedRequestHash &&
    Number.isFinite(ts) && Math.abs(Date.now() - ts) < 120000 &&
    app?.appRecognitionVerdict === 'PLAY_RECOGNIZED' &&
    Array.isArray(device?.deviceRecognitionVerdict) &&
    device.deviceRecognitionVerdict.includes('MEETS_DEVICE_INTEGRITY');

  if (!valid) {
    // Log only verdict categories, never the integrity token or request hash.
    console.warn('Play Integrity verdict rejected', {
      packageMatches: request?.requestPackageName === packageName,
      requestHashMatches: request?.requestHash === expectedRequestHash,
      timestampValid: Number.isFinite(ts) && Math.abs(Date.now() - ts) < 120000,
      appVerdict: app?.appRecognitionVerdict || 'missing',
      deviceVerdicts: device?.deviceRecognitionVerdict || [],
    });
  }

  return valid;
}

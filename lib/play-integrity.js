import { GoogleAuth } from 'google-auth-library';
import { createHash } from 'node:crypto';

const auth = new GoogleAuth({ scopes: ['https://www.googleapis.com/auth/playintegrity'] });
const sha256base64url = value => createHash('sha256').update(value).digest('base64url');

// Must match Android's Standard Integrity requestHash construction exactly.
export function registrationRequestHash(challenge, fcmToken, publicKey) {
  return sha256base64url(`bokkara-register-v1\n${challenge}\n${fcmToken}\n${publicKey}`);
}

export async function verifyAndroidIntegrity(integrityToken, expectedRequestHash) {
  if (typeof integrityToken !== 'string' || integrityToken.length < 20 || integrityToken.length > 20000) return false;
  const packageName = process.env.BOKKARA_ANDROID_PACKAGE_NAME || 'com.bokkara.app';
  const client = await auth.getClient();
  const url = `https://playintegrity.googleapis.com/v1/${encodeURIComponent(packageName)}:decodeIntegrityToken`;
  const response = await client.request({ url, method: 'POST', data: { integrity_token: integrityToken } });
  const payload = response.data?.tokenPayloadExternal;
  const request = payload?.requestDetails;
  const app = payload?.appIntegrity;
  const device = payload?.deviceIntegrity;
  const ts = Number(request?.timestampMillis);
  return request?.requestPackageName === packageName &&
    request?.requestHash === expectedRequestHash &&
    Number.isFinite(ts) && Math.abs(Date.now() - ts) < 120000 &&
    app?.appRecognitionVerdict === 'PLAY_RECOGNIZED' &&
    Array.isArray(device?.deviceRecognitionVerdict) &&
    device.deviceRecognitionVerdict.includes('MEETS_DEVICE_INTEGRITY');
}

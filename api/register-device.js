import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { getBokkaraFirestore } from '../lib/firebase.js';
import { registrationRequestHash, verifyAndroidIntegrity } from '../lib/play-integrity.js';

const sha256 = value => createHash('sha256').update(value).digest('hex');
const validChallenge = value => typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value);
const validSignature = value => typeof value === 'string' && value.length > 0 && value.length <= 512 && /^[A-Za-z0-9+/]+={0,2}$/.test(value);
const validFcmToken = value => typeof value === 'string' && value.length >= 30 && value.length <= 4096 && /^[A-Za-z0-9:_-]+$/.test(value);

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }
  const { challenge, signature, fcmToken, platform, integrityToken } = req.body || {};
  if (!validChallenge(challenge) || !validSignature(signature) || !validFcmToken(fcmToken) || platform !== 'android' || typeof integrityToken !== 'string') {
    return res.status(400).json({ success: false, error: 'Invalid registration request' });
  }
  try {
    const db = getBokkaraFirestore();
    const challengeRef = db.collection('registration_challenges').doc(sha256(challenge));
    const initial = await challengeRef.get();
    if (!initial.exists) return res.status(401).json({ success: false, error: 'Challenge not found' });
    const record = initial.data();
    if (record.used !== false || !Number.isFinite(record.expiresAt) || Date.now() >= record.expiresAt ||
        !/^gid:\/\/shopify\/Customer\/\d+$/.test(record.customerId || '') || typeof record.publicKey !== 'string') {
      return res.status(401).json({ success: false, error: 'Challenge invalid, expired, or already used' });
    }
    let verified = false;
    try {
      const key = createPublicKey({ key: Buffer.from(record.publicKey, 'base64'), format: 'der', type: 'spki' });
      verified = key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1' &&
        verifySignature('sha256', Buffer.from(challenge, 'utf8'), key, Buffer.from(signature, 'base64'));
    } catch { /* invalid key or signature */ }
    if (!verified) return res.status(401).json({ success: false, error: 'Device signature verification failed' });

    // Fail closed: no test allowlist or bypass. Requires Play Console / Play Integrity setup.
    const expectedHash = registrationRequestHash(challenge, fcmToken, record.publicKey);
    let integrityVerified = false;
    try { integrityVerified = await verifyAndroidIntegrity(integrityToken, expectedHash); }
    catch (error) { console.error('Play Integrity verification unavailable:', error.message); }
    if (!integrityVerified) return res.status(403).json({ success: false, error: 'Android app integrity verification failed' });

    const now = Date.now();
    const deviceRef = db.collection('notification_devices').doc(sha256(fcmToken));
    const result = await db.runTransaction(async transaction => {
      const [freshChallenge, deviceSnapshot] = await Promise.all([transaction.get(challengeRef), transaction.get(deviceRef)]);
      const fresh = freshChallenge.exists ? freshChallenge.data() : null;
      if (!fresh || fresh.used !== false || Date.now() >= fresh.expiresAt || fresh.customerId !== record.customerId || fresh.publicKey !== record.publicKey) {
        return { status: 401, error: 'Challenge expired or already used' };
      }
      const previous = deviceSnapshot.exists ? deviceSnapshot.data() : null;
      if (previous && previous.customerId !== record.customerId) return { status: 409, error: 'Device token already associated with another account' };
      transaction.update(challengeRef, { used: true, usedAt: now });
      transaction.set(deviceRef, {
        customerId: record.customerId, fcmToken, tokenHash: sha256(fcmToken),
        publicKeyHash: sha256(record.publicKey), platform: 'android', active: true,
        createdAt: previous?.createdAt || now, updatedAt: now, integrityVerified: true
      });
      return { status: 200 };
    });
    if (result.status !== 200) return res.status(result.status).json({ success: false, error: result.error });
    return res.status(200).json({ success: true, challengeVerified: true, deviceRegistered: true });
  } catch (error) {
    console.error('Device registration failed:', error.message);
    return res.status(500).json({ success: false, error: 'Unable to register device' });
  }
}

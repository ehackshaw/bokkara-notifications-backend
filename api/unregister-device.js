import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { getBokkaraFirestore } from '../lib/firebase.js';

const sha256 = x => createHash('sha256').update(x).digest('hex');
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return res.status(405).json({ success: false }); }
  const { fcmToken, publicKey, signature, timestamp, nonce } = req.body || {};
  if (typeof fcmToken !== 'string' || fcmToken.length < 30 || fcmToken.length > 4096 || !/^[A-Za-z0-9:_-]+$/.test(fcmToken) ||
      typeof publicKey !== 'string' || publicKey.length > 3000 || typeof signature !== 'string' || signature.length > 512 ||
      typeof nonce !== 'string' || !/^[a-f0-9]{32}$/.test(nonce) || !Number.isSafeInteger(timestamp) || Math.abs(Date.now() - timestamp) > 120000) {
    return res.status(400).json({ success: false, error: 'Invalid request' });
  }
  try {
    const key = createPublicKey({ key: Buffer.from(publicKey, 'base64'), format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return res.status(401).json({ success: false });
    const canonicalKey = key.export({ format: 'der', type: 'spki' }).toString('base64');
    const message = `bokkara-unregister-v1\n${fcmToken}\n${timestamp}\n${nonce}`;
    if (!verifySignature('sha256', Buffer.from(message), key, Buffer.from(signature, 'base64'))) return res.status(401).json({ success: false });
    const ref = getBokkaraFirestore().collection('notification_devices').doc(sha256(fcmToken));
    const result = await getBokkaraFirestore().runTransaction(async tx => {
      const snap = await tx.get(ref);
      if (!snap.exists) return 'not_found';
      if (snap.data().publicKeyHash !== sha256(canonicalKey)) return 'forbidden';
      tx.update(ref, { active: false, updatedAt: Date.now(), deactivatedAt: Date.now() });
      return 'ok';
    });
    if (result === 'forbidden') return res.status(403).json({ success: false });
    return res.status(200).json({ success: true, deactivated: result === 'ok' });
  } catch (error) {
    console.error('Unregister failed:', error.message);
    return res.status(500).json({ success: false });
  }
}

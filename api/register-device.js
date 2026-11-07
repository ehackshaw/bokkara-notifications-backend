import { createHash, createPublicKey, timingSafeEqual, verify as verifySignature } from 'node:crypto';
import { getBokkaraFirestore, getBokkaraMessaging } from '../lib/firebase.js';
import { registrationRequestHash, verifyAndroidIntegrity } from '../lib/play-integrity.js';
import { EVENTS } from '../lib/notification-events.js';

const sha256 = value => createHash('sha256').update(value).digest('hex');
const validChallenge = value => typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value);
const validSignature = value => typeof value === 'string' && value.length > 0 && value.length <= 512 && /^[A-Za-z0-9+/]+={0,2}$/.test(value);
const validFcmToken = value => typeof value === 'string' && value.length >= 30 && value.length <= 4096 && /^[A-Za-z0-9:_-]+$/.test(value);
const authorizedTest = (supplied, expected) => {
  if (typeof supplied !== 'string' || typeof expected !== 'string' || expected.length < 32) return false;
  const a = Buffer.from(supplied), b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
};

// Send a sign-in notification once per customer, after successful production device registration.
// A short lease avoids concurrent duplicate sends. Failed sends can be retried on later registration.
async function sendFirstSigninNotification(db, customerId, eligibility, fcmToken) {
  if (eligibility !== 'member' && eligibility !== 'membership_invitation') return;
  const ref = db.collection('notification_first_signin').doc(sha256(customerId));
  const now = Date.now();
  const leaseId = sha256(`${customerId}:${fcmToken}:${now}:${Math.random()}`);
  const claimed = await db.runTransaction(async tx => {
    const snapshot = await tx.get(ref);
    const record = snapshot.exists ? snapshot.data() : null;
    if (record?.status === 'sent') return false;
    if (record?.status === 'sending' && Number.isFinite(record.leaseUntil) && record.leaseUntil > now) return false;
    tx.set(ref, { customerId, status: 'sending', type: eligibility === 'member' ? 'welcome' : 'membership_invitation', leaseId, leaseUntil: now + 120000, updatedAt: now }, { merge: true });
    return true;
  });
  if (!claimed) return;
  const type = eligibility === 'member' ? 'welcome' : 'membership_invitation';
  const template = EVENTS[type];
  try {
    await getBokkaraMessaging().send({
      token: fcmToken,
      notification: { title: template.title, body: template.body },
      data: { type, path: template.path },
      android: { priority: 'high', notification: { channelId: 'bokkara_updates' } }
    });
    await db.runTransaction(async tx => {
      const current = await tx.get(ref);
      if (current.data()?.leaseId === leaseId) tx.update(ref, { status: 'sent', sentAt: Date.now(), leaseUntil: 0 });
    });
  } catch (error) {
    console.error('First sign-in push failed:', error.code || error.message);
    await db.runTransaction(async tx => {
      const current = await tx.get(ref);
      if (current.data()?.leaseId === leaseId) tx.update(ref, { status: 'retry', leaseUntil: 0, updatedAt: Date.now() });
    });
  }
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return res.status(405).json({ success: false, error: 'Method not allowed' }); }
  // Preserve existing preview-only test behavior; test devices never trigger production pushes.
  const testMode = process.env.VERCEL_ENV === 'preview' &&
    process.env.BOKKARA_ENABLE_TEST_REGISTRATION === 'true' &&
    authorizedTest(req.headers['x-bokkara-test-key'], process.env.BOKKARA_TEST_REGISTRATION_KEY);
  const { challenge, signature, fcmToken, platform, integrityToken } = req.body || {};
  if (!validChallenge(challenge) || !validSignature(signature) || !validFcmToken(fcmToken) || platform !== 'android' || (!testMode && typeof integrityToken !== 'string')) {
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
    let integrityVerified = false;
    if (!testMode) {
      const expectedHash = registrationRequestHash(challenge, fcmToken, record.publicKey);
      try { integrityVerified = await verifyAndroidIntegrity(integrityToken, expectedHash); }
      catch (error) { console.error('Play Integrity verification unavailable:', error.message); }
      if (!integrityVerified) return res.status(403).json({ success: false, error: 'Android app integrity verification failed' });
    }
    const now = Date.now();
    const deviceRef = db.collection(testMode ? 'notification_test_devices' : 'notification_devices').doc(sha256(fcmToken));
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
        createdAt: previous?.createdAt || now, updatedAt: now, integrityVerified, testOnly: testMode
      });
      return { status: 200 };
    });
    if (result.status !== 200) return res.status(result.status).json({ success: false, error: result.error });
    if (!testMode) {
      // Best effort: registration remains successful if FCM delivery fails.
      try { await sendFirstSigninNotification(db, record.customerId, record.notificationEligibility, fcmToken); }
      catch (error) { console.error('First sign-in processing failed:', error.message); }
    }
    return res.status(200).json({ success: true, challengeVerified: true, deviceRegistered: true, testOnly: testMode });
  } catch (error) {
    console.error('Device registration failed:', error.message);
    return res.status(500).json({ success: false, error: 'Unable to register device' });
  }
}

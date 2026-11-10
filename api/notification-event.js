import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { getBokkaraFirestore, getBokkaraMessaging } from '../lib/firebase.js';
import { EVENTS } from '../lib/notification-events.js';

const hash = x => createHash('sha256').update(x).digest('hex');
const compare = (a,b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a),Buffer.from(b));
const isGid = x => typeof x === 'string' && /^gid:\/\/shopify\/Customer\/[1-9]\d*$/.test(x);
const validEventId = x => typeof x === 'string' && x.length <= 160 && /^[A-Za-z0-9_.:-]+$/.test(x);
const bookingTypes = new Set(['booking_received','booking_confirmed','booking_adjusted']);
const validOrderNumber = x => typeof x === 'string' && /^[A-Za-z0-9-]{1,40}$/.test(x);
const invalidTokenCodes = new Set(['messaging/registration-token-not-registered','messaging/invalid-registration-token']);

export default async function handler(req,res) {
  res.setHeader('Cache-Control','no-store');
  if (req.method !== 'POST') { res.setHeader('Allow','POST'); return res.status(405).json({success:false,error:'Method not allowed'}); }
  // Production only. No browser access and no Android-side secret.
  if (process.env.VERCEL_ENV !== 'production') return res.status(403).json({success:false,error:'Production only'});
  const secret = process.env.BOKKARA_NOTIFICATION_EVENT_SECRET;
  if (typeof secret !== 'string' || secret.length < 32) return res.status(503).json({success:false,error:'Notification events not configured'});
  const raw = req.body;
  const event = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : null;
  if (!event || !validEventId(event.eventId) || !isGid(event.customerId) || !Object.hasOwn(EVENTS,event.type) || Object.keys(event).some(k => !['eventId','customerId','type','orderNumber'].includes(k)) || (bookingTypes.has(event.type) ? !validOrderNumber(event.orderNumber) : event.orderNumber !== undefined)) {
    return res.status(400).json({success:false,error:'Invalid event'});
  }
  // Canonical signature over exactly the validated event fields. Callers must construct the same string.
  const canonical = JSON.stringify({eventId:event.eventId,customerId:event.customerId,type:event.type,...(bookingTypes.has(event.type) ? {orderNumber:event.orderNumber} : {})});
  const expected = createHmac('sha256',secret).update(canonical).digest('hex');
  if (!compare(req.headers['x-bokkara-signature'],expected)) return res.status(401).json({success:false,error:'Unauthorized'});
  const db = getBokkaraFirestore();
  const eventRef = db.collection('notification_event_deliveries').doc(hash(event.eventId));
  const now = Date.now();
  try {
    const claimed = await db.runTransaction(async tx => {
      const existing = await tx.get(eventRef);
      if (existing.exists) return false;
      tx.create(eventRef,{eventId:event.eventId,customerId:event.customerId,type:event.type,status:'processing',createdAt:now});
      return true;
    });
    if (!claimed) return res.status(200).json({success:true,duplicate:true});
    const snapshot = await db.collection('notification_devices').where('customerId','==',event.customerId).where('active','==',true).limit(500).get();
    const docs = snapshot.docs.filter(d => d.data().integrityVerified === true && typeof d.data().fcmToken === 'string' && (!bookingTypes.has(event.type) || d.data().notificationEligibility === 'member'));
    if (!docs.length) {
      await eventRef.update({status:'no_devices',finishedAt:Date.now(),delivered:0});
      return res.status(200).json({success:true,delivered:0});
    }
    const template = EVENTS[event.type];
    const result = await getBokkaraMessaging().sendEachForMulticast({
      tokens:docs.map(d => d.data().fcmToken),
      notification:{title:template.title,body:template.body},
      data:{type:event.type,eventId:event.eventId,path:bookingTypes.has(event.type) ? `/pages/find-your-booking?order_number=${encodeURIComponent(event.orderNumber)}` : template.path},
      android:{priority:'high',notification:{channelId:'bokkara_updates'}}
    });
    await Promise.all(result.responses.map(async (r,i) => {
      if (!r.success && invalidTokenCodes.has(r.error?.code)) {
        await docs[i].ref.update({active:false,invalidatedAt:Date.now(),invalidReason:r.error.code});
      }
    }));
    await eventRef.update({status:'completed',finishedAt:Date.now(),delivered:result.successCount,failed:result.failureCount});
    return res.status(200).json({success:true,delivered:result.successCount,failed:result.failureCount});
  } catch (error) {
    console.error('Notification event delivery failed:',error.message);
    // No automatic retry: FCM may have accepted messages before an error. Review event record before retrying.
    try { await eventRef.update({status:'needs_review',lastErrorAt:Date.now()}); } catch {}
    return res.status(500).json({success:false,error:'Delivery needs review'});
  }
}

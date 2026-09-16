const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp();
const db = admin.firestore();

/* Runs every 24 hours at 02:00 Lagos time.
   Expires: trial subs, gift subs, AND paid (pro/business) subs.
   For paid expiry, writes lastPaidTier + paidExpiredAt to the user doc
   so the welcome-back banner can fire on next login. */
exports.expireSubscriptions = functions.pubsub
  .schedule('every 24 hours')
  .timeZone('Africa/Lagos')
  .onRun(async () => {
    const now = new Date().toISOString();
    const snap = await db.collection('subscriptions')
      .where('status', '==', 'active')
      .where('expiresAt', '<', now)
      .get();

    if (snap.empty) {
      console.log('No expired subscriptions.');
      return null;
    }

    const batch = db.batch();
    let count = 0;

    snap.forEach(doc => {
      const sub = doc.data();
      const wasPaid = sub.tier === 'pro' || sub.tier === 'business';
      const wasGift = sub.tier === 'gift';
      const wasTrial = sub.tier === 'trial';

      batch.update(doc.ref, {
        status: 'expired',
        tier: 'free',
        expiredAt: now,
        lastTier: sub.tier
      });

      const userPatch = {
        plan: wasGift ? 'post-gift' : 'free',
        subscriptionStatus: 'expired',
        updatedAt: now
      };
      if (wasGift) userPatch.postGiftSince = now;
      if (wasTrial) userPatch.trialExpiredAt = now;
      if (wasPaid) {
        userPatch.lastPaidTier = sub.tier;
        userPatch.paidExpiredAt = now;
      }

      batch.update(db.collection('users').doc(doc.id), userPatch);
      count++;
    });

    await batch.commit();
    console.log(`Expired ${count} subscription(s).`);
    return null;
  });


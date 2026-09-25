// ============================================================
// KreateBiz — Firebase Cloud Function
// File: functions/index.js
// ============================================================
// Runs every 24 hours at 02:00 Lagos time.
// Expires trial subs, gift subs, and paid (pro/business) subs.
// For paid expiry, writes lastPaidTier + paidExpiredAt to the
// user doc so the welcome-back banner fires on next login.
// ============================================================

const functions = require("firebase-functions");
const admin = require("firebase-admin");

admin.initializeApp();
const db = admin.firestore();

exports.expireSubscriptions = functions.pubsub
  .schedule("every 24 hours")
  .timeZone("Africa/Lagos")
  .onRun(async () => {
    const now = new Date().toISOString();

    const snap = await db
      .collection("subscriptions")
      .where("status", "==", "active")
      .where("expiresAt", "<", now)
      .get();

    if (snap.empty) {
      console.log("[expireSubscriptions] No expired subscriptions.");
      return null;
    }

    // Firestore batches cap at 500 writes; each sub needs 2 writes.
    // chunkSize = 200 subscriptions = 400 writes → safe.
    const CHUNK = 200;
    const docs = snap.docs;
    let total = 0;

    for (let i = 0; i < docs.length; i += CHUNK) {
      const chunk = docs.slice(i, i + CHUNK);
      const batch = db.batch();

      chunk.forEach((doc) => {
        const sub = doc.data();
        const wasPaid = sub.tier === "pro" || sub.tier === "business";
        const wasGift = sub.tier === "gift";
        const wasTrial = sub.tier === "trial";

        batch.update(doc.ref, {
          status: "expired",
          tier: "free",
          expiredAt: now,
          lastTier: sub.tier,
        });

        const userPatch = {
          plan: wasGift ? "post-gift" : "free",
          subscriptionStatus: "expired",
          updatedAt: now,
        };
        if (wasGift) userPatch.postGiftSince = now;
        if (wasTrial) userPatch.trialExpiredAt = now;
        if (wasPaid) {
          userPatch.lastPaidTier = sub.tier;
          userPatch.paidExpiredAt = now;
        }

        batch.update(db.collection("users").doc(doc.id), userPatch);
        total++;
      });

      await batch.commit();
    }

    console.log(`[expireSubscriptions] Expired ${total} subscription(s).`);
    return null;
  });

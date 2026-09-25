// ============================================================
// KreateBiz Cloudflare Pages Function
// File: functions/api/[[path]].js
// ============================================================
// Routes:
//   GET  /api/health
//   GET  /api/flutterwave-check
//   POST /api/initiate-payment
//   POST /api/verify-payment          ← NEW (verify by tx id / ref)
//   POST /api/flutterwave-webhook
//   POST /api/admin/extend
//   POST /api/admin/cancel
// ============================================================

const TOKEN_CACHE = { token: null, expires: 0 };

// ------------------------------------------------------------
// CORS
// ------------------------------------------------------------
function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonResponse(data, status = 200, cors = corsHeaders()) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

// ------------------------------------------------------------
// HELPERS
// ------------------------------------------------------------
function getFlutterwaveSecret(env) {
  const raw = env.FLW_SECRET_KEY;
  if (!raw) throw new Error("FLW_SECRET_KEY is missing from Cloudflare environment.");
  const key = String(raw).trim().replace(/^["']|["']$/g, "").trim();
  if (!key) throw new Error("FLW_SECRET_KEY exists but is empty.");
  return key;
}

function getFrontendUrl(env, fallbackOrigin) {
  let url = env.FRONTEND_URL || fallbackOrigin || "";
  url = String(url).replace(/\/+$/, "");
  return url;
}

function buildRedirectUrl(env, fallbackOrigin, userId) {
  const base = getFrontendUrl(env, fallbackOrigin);
  return `${base}/?payment=callback&uid=${encodeURIComponent(userId)}`;
}

// ------------------------------------------------------------
// FIREBASE SERVICE ACCOUNT ACCESS TOKEN
// ------------------------------------------------------------
async function getAccessToken(env) {
  if (TOKEN_CACHE.token && TOKEN_CACHE.expires > Date.now() + 60000) {
    return TOKEN_CACHE.token;
  }
  if (!env.FIREBASE_SERVICE_ACCOUNT) throw new Error("FIREBASE_SERVICE_ACCOUNT is missing.");

  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const now = Math.floor(Date.now() / 1000);

  const b64url = (s) =>
    btoa(s).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");

  const enc = (obj) =>
    b64url(unescape(encodeURIComponent(JSON.stringify(obj))));

  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: sa.token_uri,
    exp: now + 3600,
    iat: now,
  };

  const unsigned = `${enc(header)}.${enc(payload)}`;
  const pem = sa.private_key.replace(/\\n/g, "\n");
  const key = await importPrivateKey(pem);

  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsigned)
  );

  const sigB64 = b64url(String.fromCharCode(...new Uint8Array(sig)));
  const jwt = `${unsigned}.${sigB64}`;

  const res = await fetch(sa.token_uri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body:
      `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` +
      `&assertion=${jwt}`,
  });

  if (!res.ok) throw new Error("Firebase token exchange failed: " + (await res.text()));

  const data = await res.json();
  TOKEN_CACHE.token = data.access_token;
  TOKEN_CACHE.expires = Date.now() + data.expires_in * 1000;
  return data.access_token;
}

async function importPrivateKey(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s/g, "");
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

// ------------------------------------------------------------
// FIRESTORE WRITE (PATCH — creates or merges)
// ------------------------------------------------------------
async function fsWrite(env, path, data) {
  const token = await getAccessToken(env);
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);

  const fields = {};
  for (const [k, v] of Object.entries(data)) {
    if (v === null || v === undefined) continue;

    if (v && typeof v === "object" && v.__ts) {
      fields[k] = { timestampValue: v.value };
    } else if (typeof v === "number" && Number.isFinite(v)) {
      fields[k] = { doubleValue: v };
    } else if (typeof v === "boolean") {
      fields[k] = { booleanValue: v };
    } else {
      fields[k] = { stringValue: String(v) };
    }
  }

  const url =
    `https://firestore.googleapis.com/v1/` +
    `projects/${sa.project_id}` +
    `/databases/(default)/documents/${path}`;

  const res = await fetch(url, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ fields }),
  });

  if (!res.ok) throw new Error("Firestore write failed: " + (await res.text()));
  return res.json();
}

// ------------------------------------------------------------
// FIRESTORE READ
// ------------------------------------------------------------
async function fsRead(env, path) {
  const token = await getAccessToken(env);
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);

  const url =
    `https://firestore.googleapis.com/v1/` +
    `projects/${sa.project_id}` +
    `/databases/(default)/documents/${path}`;

  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) return null;

  const doc = await res.json();
  const out = {};
  for (const [k, v] of Object.entries(doc.fields || {})) {
    if (v.stringValue !== undefined) out[k] = v.stringValue;
    else if (v.integerValue !== undefined) out[k] = Number(v.integerValue);
    else if (v.doubleValue !== undefined) out[k] = Number(v.doubleValue);
    else if (v.booleanValue !== undefined) out[k] = v.booleanValue;
    else if (v.timestampValue !== undefined) out[k] = v.timestampValue;
  }
  return out;
}

// ------------------------------------------------------------
// SUBSCRIPTION ACTIVATION (shared by webhook + verify)
// Extends existing active subscription if any.
// ------------------------------------------------------------
async function activateSubscription(env, opts) {
  const {
    userId,
    planName = "KreateBiz Pro",
    planId = "",
    interval = "monthly",
    txRef = "",
    amount = 0,
    email = "",
    transactionId = "",
  } = opts;

  if (!userId) throw new Error("activateSubscription: userId required");

  const now = new Date();

  // Extend if still active; otherwise start from now.
  const existing = await fsRead(env, `subscriptions/${userId}`);
  let baseDate = now;
  if (existing && existing.expiresAt) {
    const prev = new Date(existing.expiresAt);
    if (!isNaN(prev.getTime()) && prev > now) baseDate = prev;
  }

  const expiresAt = new Date(baseDate);
  if (String(interval).toLowerCase() === "yearly") {
    expiresAt.setFullYear(expiresAt.getFullYear() + 1);
  } else {
    expiresAt.setMonth(expiresAt.getMonth() + 1);
  }

  let tier = "pro";
  if (String(planName).toLowerCase().includes("business")) tier = "business";

  const nowIso = now.toISOString();
  const expIso = expiresAt.toISOString();

  await fsWrite(env, `subscriptions/${userId}`, {
    userId,
    planId: String(planId || ""),
    planName,
    tier,
    status: "active",
    startedAt: { __ts: true, value: nowIso },
    expiresAt: { __ts: true, value: expIso },
    lastReference: txRef || "",
    lastAmount: Number(amount || 0),
    updatedAt: { __ts: true, value: nowIso },
  });

  await fsWrite(env, `users/${userId}`, {
    plan: tier,
    subscriptionStatus: "active",
    updatedAt: { __ts: true, value: nowIso },
  });

  const paymentKey =
    String(transactionId || txRef || `${userId}-${Date.now()}`).replace(/[\/\s]/g, "_");

  await fsWrite(env, `payments/${paymentKey}`, {
    userId,
    email: email || "",
    amount: Number(amount || 0),
    status: "successful",
    planName,
    reference: txRef || "",
    createdAt: { __ts: true, value: nowIso },
  });

  return { tier, expiresAt: expIso, paymentKey };
}

// ============================================================
// MAIN ROUTER
// ============================================================
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const cors = corsHeaders();

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: cors });
  }

  // Pathname will be like /api/xxx
  let route = url.pathname.replace(/^\/api/, "");
  if (!route) route = "/";

  try {
    if (route === "/health" || route === "/") {
      return new Response("OK", { headers: cors });
    }

    if (route === "/flutterwave-check") {
      return await flutterwaveCheck(env, cors);
    }

    if (route === "/initiate-payment") {
      return await initiatePayment(request, env, cors, url.origin);
    }

    if (route === "/verify-payment") {
      return await verifyPayment(request, env, cors);
    }

    if (route === "/flutterwave-webhook") {
      return await handleWebhook(request, env);
    }

    if (route === "/admin/extend") {
      return await adminExtend(request, env, cors);
    }

    if (route === "/admin/cancel") {
      return await adminCancel(request, env, cors);
    }
  } catch (err) {
    console.error("KreateBiz Worker error:", err);
    return jsonResponse(
      { error: err?.message || "Internal server error." },
      500,
      cors
    );
  }

  return new Response("Not found", { status: 404, headers: cors });
}

// ============================================================
// FLUTTERWAVE CONNECTION CHECK
// ============================================================
async function flutterwaveCheck(env, cors) {
  let secret;
  try {
    secret = getFlutterwaveSecret(env);
  } catch (err) {
    return jsonResponse(
      { ok: false, service: "flutterwave", error: err.message },
      500,
      cors
    );
  }

  const keyPrefix = secret.substring(0, Math.min(10, secret.length));

  const response = await fetch("https://api.flutterwave.com/v3/payment-plans", {
    method: "GET",
    headers: {
      Authorization: `Bearer ${secret}`,
      "Content-Type": "application/json",
    },
  });

  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }

  if (!response.ok) {
    return jsonResponse(
      {
        ok: false,
        service: "flutterwave",
        upstreamStatus: response.status,
        flutterwaveMessage:
          data?.message || data?.error || "Flutterwave rejected the API request.",
        keyPresent: true,
        keyPrefix,
        keyLength: secret.length,
      },
      502,
      cors
    );
  }

  return jsonResponse(
    {
      ok: true,
      service: "flutterwave",
      message: "Cloudflare can successfully authenticate with Flutterwave.",
      upstreamStatus: response.status,
      keyPresent: true,
      keyPrefix,
      keyLength: secret.length,
      plansFound: Array.isArray(data?.data) ? data.data.length : null,
    },
    200,
    cors
  );
}

// ============================================================
// INITIATE PAYMENT
// ============================================================
async function initiatePayment(request, env, cors, fallbackOrigin) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON body." }, 400, cors);
  }

  const { email, planId, amount, userId, planName, interval } = body;

  if (!email || !amount || !userId) {
    return jsonResponse(
      { error: "Missing required payment fields (email, amount, userId)." },
      400,
      cors
    );
  }

  const secret = getFlutterwaveSecret(env);

  if (secret.includes("_TEST")) {
    return jsonResponse(
      {
        error:
          "Cloudflare is using a Flutterwave TEST secret key. Production requires the LIVE secret key.",
      },
      500,
      cors
    );
  }

  const txRef = `KB-${userId}-${Date.now()}`;

  const payload = {
    tx_ref: txRef,
    amount: Number(amount),
    currency: "NGN",
    redirect_url: buildRedirectUrl(env, fallbackOrigin, userId),
    customer: {
      email: String(email).trim(),
      name: String(email).trim(),
    },
    customizations: {
      title: "KreateBiz Subscription",
      description: `${planName || "Subscription"} (${interval || "monthly"})`,
    },
    meta: {
      userId: String(userId),
      planId: String(planId || ""),
      planName: planName || "KreateBiz Pro",
      interval: interval || "monthly",
    },
  };

  // Attach the Flutterwave payment plan only when it looks like a real numeric id.
  const numericPlan = Number(planId);
  if (planId && Number.isFinite(numericPlan) && numericPlan > 0) {
    payload.payment_plan = numericPlan;
  }

  console.log("Starting Flutterwave payment:", {
    planId: payload.payment_plan || "(none)",
    amount: payload.amount,
    currency: payload.currency,
    email: payload.customer.email,
    interval: payload.meta.interval,
    txRef,
  });

  const res = await fetch("https://api.flutterwave.com/v3/payments", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${secret}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { message: text };
  }

  if (!res.ok) {
    console.error("Flutterwave payment API error:", {
      status: res.status,
      response: data,
    });
    return jsonResponse(
      {
        error:
          data?.message ||
          data?.error ||
          "Flutterwave rejected the payment request.",
        upstreamStatus: res.status,
        secretConfigured: true,
        secretPrefix: secret.substring(0, Math.min(10, secret.length)),
        secretLength: secret.length,
      },
      502,
      cors
    );
  }

  if (!data || data.status !== "success") {
    return jsonResponse(
      {
        error:
          data?.message ||
          "Flutterwave did not return a successful payment response.",
        upstreamStatus: res.status,
      },
      502,
      cors
    );
  }

  return jsonResponse(data, 200, cors);
}

// ============================================================
// VERIFY PAYMENT  (POST { transactionId } or { txRef })
// ------------------------------------------------------------
// Useful right after Flutterwave redirects the user back,
// in case the webhook has not fired yet.
// ============================================================
async function verifyPayment(request, env, cors) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON body." }, 400, cors);
  }

  const { transactionId, txRef } = body || {};
  if (!transactionId && !txRef) {
    return jsonResponse(
      { error: "Provide transactionId or txRef." },
      400,
      cors
    );
  }

  const secret = getFlutterwaveSecret(env);

  const verifyUrl = transactionId
    ? `https://api.flutterwave.com/v3/transactions/${encodeURIComponent(
        transactionId
      )}/verify`
    : `https://api.flutterwave.com/v3/transactions/verify_by_reference?tx_ref=${encodeURIComponent(
        txRef
      )}`;

  const res = await fetch(verifyUrl, {
    headers: { Authorization: `Bearer ${secret}` },
  });

  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { message: text };
  }

  if (!res.ok || data.status !== "success") {
    return jsonResponse(
      {
        ok: false,
        error: data?.message || "Flutterwave verification failed.",
        upstreamStatus: res.status,
      },
      502,
      cors
    );
  }

  const tx = data.data || {};
  const txStatus = String(tx.status || "").toLowerCase();

  if (txStatus !== "successful") {
    return jsonResponse(
      { ok: false, status: tx.status || "unknown", error: "Transaction not successful." },
      200,
      cors
    );
  }

  const userId = tx?.meta?.userId || tx?.meta?.user_id;
  if (!userId) {
    return jsonResponse(
      { ok: false, error: "Missing userId in transaction metadata." },
      400,
      cors
    );
  }

  const result = await activateSubscription(env, {
    userId,
    planName: tx?.meta?.planName || "KreateBiz Pro",
    planId: tx?.meta?.planId || "",
    interval: tx?.meta?.interval || "monthly",
    txRef: tx.tx_ref || txRef || "",
    amount: tx.amount || 0,
    email: tx?.customer?.email || "",
    transactionId: tx.id || transactionId || "",
  });

  return jsonResponse(
    { ok: true, tier: result.tier, expiresAt: result.expiresAt },
    200,
    cors
  );
}

// ============================================================
// FLUTTERWAVE WEBHOOK
// ============================================================
async function handleWebhook(request, env) {
  const verifHash = request.headers.get("verif-hash");
  if (!verifHash || verifHash !== env.FLW_SECRET_HASH) {
    console.warn("Invalid Flutterwave webhook signature.");
    return new Response("Unauthorized", { status: 401 });
  }

  let payload;
  try {
    payload = await request.json();
  } catch {
    return new Response("OK", { status: 200 });
  }

  const { event, data } = payload || {};

  // -------- SUCCESSFUL CHARGE --------
  if (event === "charge.completed" && data?.status === "successful") {
    const userId = data?.meta?.userId;
    if (!userId) {
      console.warn("Webhook received without userId.");
      return new Response("OK", { status: 200 });
    }

    try {
      await activateSubscription(env, {
        userId,
        planName: data?.meta?.planName || "KreateBiz Pro",
        planId: data?.meta?.planId || "",
        interval: data?.meta?.interval || "monthly",
        txRef: data?.tx_ref || "",
        amount: data?.amount || 0,
        email: data?.customer?.email || "",
        transactionId: data?.id || "",
      });
      console.log(`Subscription activated via webhook: ${userId}`);
    } catch (err) {
      console.error("Webhook activation failed:", err);
      // Return 500 so Flutterwave retries
      return new Response("Error", { status: 500 });
    }
  }

  // -------- CANCELLED SUBSCRIPTION --------
  if (event === "subscription.cancelled") {
    const userId = data?.meta?.userId;
    if (userId) {
      const now = new Date().toISOString();
      try {
        await fsWrite(env, `subscriptions/${userId}`, {
          status: "cancelled",
          updatedAt: { __ts: true, value: now },
        });
        await fsWrite(env, `users/${userId}`, {
          subscriptionStatus: "cancelled",
          updatedAt: { __ts: true, value: now },
        });
      } catch (err) {
        console.error("Webhook cancel failed:", err);
      }
    }
  }

  return new Response("OK", { status: 200 });
}

// ============================================================
// ADMIN EXTEND
// ============================================================
async function adminExtend(request, env, cors) {
  const { userId, days, adminEmail } = await request.json();

  if (adminEmail !== env.ADMIN_EMAIL) {
    return jsonResponse({ error: "Unauthorized" }, 403, cors);
  }
  if (!userId) {
    return jsonResponse({ error: "Missing userId." }, 400, cors);
  }

  const sub = await fsRead(env, `subscriptions/${userId}`);
  const current = sub?.expiresAt ? new Date(sub.expiresAt) : new Date();
  const base = isNaN(current.getTime()) || current < new Date() ? new Date() : current;

  base.setDate(base.getDate() + Number(days || 30));

  const now = new Date().toISOString();

  await fsWrite(env, `subscriptions/${userId}`, {
    status: "active",
    expiresAt: { __ts: true, value: base.toISOString() },
    updatedAt: { __ts: true, value: now },
  });

  await fsWrite(env, `users/${userId}`, {
    subscriptionStatus: "active",
    updatedAt: { __ts: true, value: now },
  });

  return jsonResponse({ ok: true, expiresAt: base.toISOString() }, 200, cors);
}

// ============================================================
// ADMIN CANCEL
// ============================================================
async function adminCancel(request, env, cors) {
  const { userId, adminEmail } = await request.json();

  if (adminEmail !== env.ADMIN_EMAIL) {
    return jsonResponse({ error: "Unauthorized" }, 403, cors);
  }
  if (!userId) {
    return jsonResponse({ error: "Missing userId." }, 400, cors);
  }

  const now = new Date().toISOString();

  await fsWrite(env, `subscriptions/${userId}`, {
    status: "cancelled",
    updatedAt: { __ts: true, value: now },
  });

  await fsWrite(env, `users/${userId}`, {
    plan: "free",
    subscriptionStatus: "cancelled",
    updatedAt: { __ts: true, value: now },
  });

  return jsonResponse({ ok: true }, 200, cors);
      }

// KreateBiz Cloudflare Pages Function
// Handles: /api/initiate-payment, /api/flutterwave-webhook, /api/admin/extend, /api/admin/cancel, /api/health

const TOKEN_CACHE = { token: null, expires: 0 };

async function getAccessToken(env) {
  if (TOKEN_CACHE.token && TOKEN_CACHE.expires > Date.now() + 60000) return TOKEN_CACHE.token;
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const now = Math.floor(Date.now() / 1000);
  const b64url = (s) => btoa(s).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  const enc = (obj) => b64url(unescape(encodeURIComponent(JSON.stringify(obj))));
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
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned));
  const sigB64 = b64url(String.fromCharCode(...new Uint8Array(sig)));
  const jwt = `${unsigned}.${sigB64}`;
  const res = await fetch(sa.token_uri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });
  if (!res.ok) throw new Error("Token exchange failed: " + (await res.text()));
  const data = await res.json();
  TOKEN_CACHE.token = data.access_token;
  TOKEN_CACHE.expires = Date.now() + data.expires_in * 1000;
  return data.access_token;
}

async function importPrivateKey(pem) {
  const b64 = pem.replace(/-----BEGIN PRIVATE KEY-----/, "").replace(/-----END PRIVATE KEY-----/, "").replace(/\s/g, "");
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
}

async function fsWrite(env, path, data, merge) {
  const token = await getAccessToken(env);
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const fields = {};
  for (const [k, v] of Object.entries(data)) {
    if (v === null || v === undefined) continue;
    if (v && typeof v === "object" && v.__ts) fields[k] = { timestampValue: v.value };
    else if (typeof v === "number") fields[k] = { integerValue: String(v) };
    else if (typeof v === "boolean") fields[k] = { booleanValue: v };
    else fields[k] = { stringValue: String(v) };
  }
  const url = `https://firestore.googleapis.com/v1/projects/${sa.project_id}/databases/(default)/documents/${path}`;
  const method = merge ? "PATCH" : "PATCH";
  const res = await fetch(url, {
    method: method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ fields }),
  });
  if (!res.ok) throw new Error("Firestore write failed: " + (await res.text()));
  return res.json();
}

async function fsRead(env, path) {
  const token = await getAccessToken(env);
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const url = `https://firestore.googleapis.com/v1/projects/${sa.project_id}/databases/(default)/documents/${path}`;
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

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
  if (request.method === "OPTIONS") return new Response(null, { headers: cors });

  const route = url.pathname.replace(/^\/api/, "");

  try {
    if (route === "/health") return new Response("OK", { headers: cors });
    if (route === "/initiate-payment") return await initiatePayment(request, env, cors);
    if (route === "/flutterwave-webhook") return await handleWebhook(request, env);
    if (route === "/admin/extend") return await adminExtend(request, env, cors);
    if (route === "/admin/cancel") return await adminCancel(request, env, cors);
  } catch (err) {
    console.error("Worker error:", err);
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...cors, "Content-Type": "application/json" },
    });
  }
  return new Response("Not found", { status: 404, headers: cors });
}

async function initiatePayment(request, env, cors) {
  const body = await request.json();
  const { email, planId, amount, userId, planName, interval } = body;

  if (!email || !planId || !amount || !userId) {
    return new Response(JSON.stringify({ error: "Missing required fields." }), {
      status: 400,
      headers: { ...cors, "Content-Type": "application/json" },
    });
  }

  const res = await fetch("https://api.flutterwave.com/v3/payments", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.FLW_SECRET_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      tx_ref: `KB-${userId}-${Date.now()}`,
      amount: amount,
      currency: "NGN",
      redirect_url: `${env.FRONTEND_URL}/?payment=callback`,
      payment_plan: planId,
      customer: { email },
      customizations: {
        title: "KreateBiz Subscription",
        description: `${planName} (${interval})`,
      },
      meta: {
        userId,
        planId: String(planId),
        planName,
        interval,
      },
    }),
  });

  const data = await res.json();
  if (!res.ok || !data.status || data.status !== "success") {
    return new Response(JSON.stringify({ error: data.message || "Flutterwave rejected the request." }), {
      status: 502,
      headers: { ...cors, "Content-Type": "application/json" },
    });
  }
  return new Response(JSON.stringify(data), {
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

async function handleWebhook(request, env) {
  const verifHash = request.headers.get("verif-hash");
  if (verifHash !== env.FLW_SECRET_HASH) {
    console.warn("Invalid Flutterwave signature");
    return new Response("Unauthorized", { status: 401 });
  }
  const payload = await request.json();
  const { event, data } = payload;

  if (event === "charge.completed" && data.status === "successful") {
    const userId = data.meta && data.meta.userId;
    const planId = data.meta && data.meta.planId;
    const planName = (data.meta && data.meta.planName) || "KreateBiz Pro";
    const interval = (data.meta && data.meta.interval) || "monthly";
    if (!userId) return new Response("OK", { status: 200 });

    const now = new Date();
    const expiresAt = new Date(now);
    if (interval === "yearly") expiresAt.setFullYear(expiresAt.getFullYear() + 1);
    else expiresAt.setMonth(expiresAt.getMonth() + 1);

    let tier = "pro";
    if (planName.toLowerCase().includes("business")) tier = "business";

    await fsWrite(env, `subscriptions/${userId}`, {
      userId,
      planId: String(planId || ""),
      planName,
      tier,
      status: "active",
      startedAt: { __ts: true, value: now.toISOString() },
      expiresAt: { __ts: true, value: expiresAt.toISOString() },
      lastReference: data.tx_ref || "",
      lastAmount: data.amount || 0,
      updatedAt: { __ts: true, value: now.toISOString() },
    });

    await fsWrite(env, `users/${userId}`, {
      plan: tier,
      subscriptionStatus: "active",
      updatedAt: { __ts: true, value: now.toISOString() },
    });

    await fsWrite(env, `payments/${data.id || data.tx_ref}`, {
      userId,
      email: (data.customer && data.customer.email) || "",
      amount: data.amount || 0,
      status: "successful",
      planName,
      reference: data.tx_ref || "",
      createdAt: { __ts: true, value: now.toISOString() },
    });

    console.log(`Subscription activated: ${userId} → ${tier} until ${expiresAt.toISOString()}`);
  }

  if (event === "subscription.cancelled") {
    const userId = data.meta && data.meta.userId;
    if (userId) {
      await fsWrite(env, `subscriptions/${userId}`, {
        status: "cancelled",
        updatedAt: { __ts: true, value: new Date().toISOString() },
      });
      await fsWrite(env, `users/${userId}`, {
        subscriptionStatus: "cancelled",
        updatedAt: { __ts: true, value: new Date().toISOString() },
      });
    }
  }

  return new Response("OK", { status: 200 });
}

async function adminExtend(request, env, cors) {
  const { userId, days, adminEmail } = await request.json();
  if (adminEmail !== env.ADMIN_EMAIL) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 403, headers: cors });
  }
  const sub = await fsRead(env, `subscriptions/${userId}`);
  const current = sub && sub.expiresAt ? new Date(sub.expiresAt) : new Date();
  current.setDate(current.getDate() + Number(days));
  await fsWrite(env, `subscriptions/${userId}`, {
    status: "active",
    expiresAt: { __ts: true, value: current.toISOString() },
    updatedAt: { __ts: true, value: new Date().toISOString() },
  });
  await fsWrite(env, `users/${userId}`, {
    subscriptionStatus: "active",
    updatedAt: { __ts: true, value: new Date().toISOString() },
  });
  return new Response(JSON.stringify({ ok: true, expiresAt: current.toISOString() }), {
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

async function adminCancel(request, env, cors) {
  const { userId, adminEmail } = await request.json();
  if (adminEmail !== env.ADMIN_EMAIL) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 403, headers: cors });
  }
  await fsWrite(env, `subscriptions/${userId}`, {
    status: "cancelled",
    updatedAt: { __ts: true, value: new Date().toISOString() },
  });
  await fsWrite(env, `users/${userId}`, {
    plan: "free",
    subscriptionStatus: "cancelled",
    updatedAt: { __ts: true, value: new Date().toISOString() },
  });
  return new Response(JSON.stringify({ ok: true }), {
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

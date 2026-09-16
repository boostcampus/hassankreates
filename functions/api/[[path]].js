// ============================================================
// KreateBiz Cloudflare Pages Function
// ============================================================
// Handles:
// GET  /api/health
// GET  /api/flutterwave-check
// POST /api/initiate-payment
// POST /api/flutterwave-webhook
// POST /api/admin/extend
// POST /api/admin/cancel
// ============================================================

const TOKEN_CACHE = {
  token: null,
  expires: 0,
};

// ============================================================
// HELPERS
// ============================================================

function jsonResponse(data, status = 200, cors = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...cors,
      "Content-Type": "application/json",
    },
  });
}

function getFlutterwaveSecret(env) {
  // Read the Cloudflare secret.
  // Remove accidental spaces and accidental surrounding quotes.
  const raw = env.FLW_SECRET_KEY;

  if (!raw) {
    throw new Error("FLW_SECRET_KEY is missing from Cloudflare environment.");
  }

  const key = String(raw)
    .trim()
    .replace(/^["']|["']$/g, "")
    .trim();

  if (!key) {
    throw new Error("FLW_SECRET_KEY exists but is empty.");
  }

  return key;
}

// ============================================================
// FIREBASE SERVICE ACCOUNT ACCESS TOKEN
// ============================================================

async function getAccessToken(env) {
  if (
    TOKEN_CACHE.token &&
    TOKEN_CACHE.expires > Date.now() + 60000
  ) {
    return TOKEN_CACHE.token;
  }

  if (!env.FIREBASE_SERVICE_ACCOUNT) {
    throw new Error("FIREBASE_SERVICE_ACCOUNT is missing.");
  }

  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);

  const now = Math.floor(Date.now() / 1000);

  const b64url = (s) =>
    btoa(s)
      .replace(/=+$/, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

  const enc = (obj) =>
    b64url(
      unescape(
        encodeURIComponent(JSON.stringify(obj))
      )
    );

  const header = {
    alg: "RS256",
    typ: "JWT",
  };

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

  const sigB64 = b64url(
    String.fromCharCode(...new Uint8Array(sig))
  );

  const jwt = `${unsigned}.${sigB64}`;

  const res = await fetch(sa.token_uri, {
    method: "POST",
    headers: {
      "Content-Type":
        "application/x-www-form-urlencoded",
    },
    body:
      `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` +
      `&assertion=${jwt}`,
  });

  if (!res.ok) {
    throw new Error(
      "Firebase token exchange failed: " +
        (await res.text())
    );
  }

  const data = await res.json();

  TOKEN_CACHE.token = data.access_token;
  TOKEN_CACHE.expires =
    Date.now() + data.expires_in * 1000;

  return data.access_token;
}

async function importPrivateKey(pem) {
  const b64 = pem
    .replace(
      /-----BEGIN PRIVATE KEY-----/,
      ""
    )
    .replace(
      /-----END PRIVATE KEY-----/,
      ""
    )
    .replace(/\s/g, "");

  const der = Uint8Array.from(
    atob(b64),
    (c) => c.charCodeAt(0)
  );

  return crypto.subtle.importKey(
    "pkcs8",
    der,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );
}

// ============================================================
// FIRESTORE WRITE
// ============================================================

async function fsWrite(env, path, data) {
  const token = await getAccessToken(env);

  const sa = JSON.parse(
    env.FIREBASE_SERVICE_ACCOUNT
  );

  const fields = {};

  for (const [k, v] of Object.entries(data)) {
    if (v === null || v === undefined) continue;

    if (
      v &&
      typeof v === "object" &&
      v.__ts
    ) {
      fields[k] = {
        timestampValue: v.value,
      };
    } else if (typeof v === "number") {
      fields[k] = {
        doubleValue: v,
      };
    } else if (typeof v === "boolean") {
      fields[k] = {
        booleanValue: v,
      };
    } else {
      fields[k] = {
        stringValue: String(v),
      };
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
    body: JSON.stringify({
      fields,
    }),
  });

  if (!res.ok) {
    throw new Error(
      "Firestore write failed: " +
        (await res.text())
    );
  }

  return res.json();
}

// ============================================================
// FIRESTORE READ
// ============================================================

async function fsRead(env, path) {
  const token = await getAccessToken(env);

  const sa = JSON.parse(
    env.FIREBASE_SERVICE_ACCOUNT
  );

  const url =
    `https://firestore.googleapis.com/v1/` +
    `projects/${sa.project_id}` +
    `/databases/(default)/documents/${path}`;

  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!res.ok) return null;

  const doc = await res.json();

  const out = {};

  for (const [k, v] of Object.entries(
    doc.fields || {}
  )) {
    if (v.stringValue !== undefined) {
      out[k] = v.stringValue;
    } else if (v.integerValue !== undefined) {
      out[k] = Number(v.integerValue);
    } else if (v.doubleValue !== undefined) {
      out[k] = Number(v.doubleValue);
    } else if (v.booleanValue !== undefined) {
      out[k] = v.booleanValue;
    } else if (v.timestampValue !== undefined) {
      out[k] = v.timestampValue;
    }
  }

  return out;
}

// ============================================================
// MAIN ROUTER
// ============================================================

export async function onRequest(context) {
  const { request, env } = context;

  const url = new URL(request.url);

  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods":
      "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, {
      headers: cors,
    });
  }

  const route = url.pathname.replace(
    /^\/api/,
    ""
  );

  try {
    // --------------------------------------------------------
    // HEALTH
    // --------------------------------------------------------

    if (route === "/health") {
      return new Response("OK", {
        headers: cors,
      });
    }

    // --------------------------------------------------------
    // FLUTTERWAVE CONNECTION CHECK
    // --------------------------------------------------------

    if (route === "/flutterwave-check") {
      return await flutterwaveCheck(env, cors);
    }

    // --------------------------------------------------------
    // PAYMENT
    // --------------------------------------------------------

    if (route === "/initiate-payment") {
      return await initiatePayment(
        request,
        env,
        cors
      );
    }

    // --------------------------------------------------------
    // WEBHOOK
    // --------------------------------------------------------

    if (route === "/flutterwave-webhook") {
      return await handleWebhook(
        request,
        env
      );
    }

    // --------------------------------------------------------
    // ADMIN
    // --------------------------------------------------------

    if (route === "/admin/extend") {
      return await adminExtend(
        request,
        env,
        cors
      );
    }

    if (route === "/admin/cancel") {
      return await adminCancel(
        request,
        env,
        cors
      );
    }

  } catch (err) {
    console.error(
      "KreateBiz Worker error:",
      err
    );

    return jsonResponse(
      {
        error:
          err?.message ||
          "Internal server error.",
      },
      500,
      cors
    );
  }

  return new Response("Not found", {
    status: 404,
    headers: cors,
  });
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
      {
        ok: false,
        service: "flutterwave",
        error: err.message,
      },
      500,
      cors
    );
  }

  // Never return the actual key.
  const keyPrefix = secret.substring(
    0,
    Math.min(10, secret.length)
  );

  const response = await fetch(
    "https://api.flutterwave.com/v3/payment-plans",
    {
      method: "GET",
      headers: {
        Authorization: `Bearer ${secret}`,
        "Content-Type": "application/json",
      },
    }
  );

  const text = await response.text();

  let data;

  try {
    data = JSON.parse(text);
  } catch {
    data = {
      raw: text,
    };
  }

  if (!response.ok) {
    console.error(
      "Flutterwave authentication check failed:",
      response.status,
      data
    );

    return jsonResponse(
      {
        ok: false,
        service: "flutterwave",
        upstreamStatus: response.status,
        flutterwaveMessage:
          data?.message ||
          data?.error ||
          "Flutterwave rejected the API request.",
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
      message:
        "Cloudflare can successfully authenticate with Flutterwave.",
      upstreamStatus: response.status,
      keyPresent: true,
      keyPrefix,
      keyLength: secret.length,
      plansFound:
        Array.isArray(data?.data)
          ? data.data.length
          : null,
    },
    200,
    cors
  );
}

// ============================================================
// INITIATE PAYMENT
// ============================================================

async function initiatePayment(
  request,
  env,
  cors
) {
  const body = await request.json();

  const {
    email,
    planId,
    amount,
    userId,
    planName,
    interval,
  } = body;

  if (
    !email ||
    !planId ||
    !amount ||
    !userId
  ) {
    return jsonResponse(
      {
        error:
          "Missing required payment fields.",
      },
      400,
      cors
    );
  }

  const secret = getFlutterwaveSecret(env);

  // Extra validation to prevent accidental test/live mismatch.
  if (secret.includes("_TEST")) {
    return jsonResponse(
      {
        error:
          "Cloudflare is using a Flutterwave TEST secret key. Your KreateBiz production payment flow requires the LIVE secret key.",
      },
      500,
      cors
    );
  }

  const payload = {
    tx_ref:
      `KB-${userId}-${Date.now()}`,

    amount: Number(amount),

    currency: "NGN",

    redirect_url:
      `${env.FRONTEND_URL}/?payment=callback`,

    payment_plan: Number(planId),

    customer: {
      email: String(email).trim(),
    },

    customizations: {
      title:
        "KreateBiz Subscription",

      description:
        `${planName || "Subscription"} ` +
        `(${interval || "monthly"})`,
    },

    meta: {
      userId: String(userId),
      planId: String(planId),
      planName:
        planName || "KreateBiz Pro",
      interval:
        interval || "monthly",
    },
  };

  console.log(
    "Starting Flutterwave payment:",
    {
      planId: payload.payment_plan,
      amount: payload.amount,
      currency: payload.currency,
      email: payload.customer.email,
      interval: payload.meta.interval,
    }
  );

  const res = await fetch(
    "https://api.flutterwave.com/v3/payments",
    {
      method: "POST",

      headers: {
        Authorization:
          `Bearer ${secret}`,

        "Content-Type":
          "application/json",
      },

      body: JSON.stringify(payload),
    }
  );

  const text = await res.text();

  let data;

  try {
    data = JSON.parse(text);
  } catch {
    data = {
      message: text,
    };
  }

  if (!res.ok) {
    console.error(
      "Flutterwave payment API error:",
      {
        status: res.status,
        response: data,
      }
    );

    return jsonResponse(
      {
        error:
          data?.message ||
          data?.error ||
          "Flutterwave rejected the payment request.",

        upstreamStatus: res.status,

        // Safe debugging information.
        // Secret key itself is NEVER returned.
        secretConfigured: true,
        secretPrefix:
          secret.substring(
            0,
            Math.min(10, secret.length)
          ),
        secretLength: secret.length,
      },
      502,
      cors
    );
  }

  if (
    !data ||
    data.status !== "success"
  ) {
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

  return jsonResponse(
    data,
    200,
    cors
  );
}

// ============================================================
// FLUTTERWAVE WEBHOOK
// ============================================================

async function handleWebhook(
  request,
  env
) {
  const verifHash =
    request.headers.get("verif-hash");

  if (
    !verifHash ||
    verifHash !== env.FLW_SECRET_HASH
  ) {
    console.warn(
      "Invalid Flutterwave webhook signature."
    );

    return new Response(
      "Unauthorized",
      {
        status: 401,
      }
    );
  }

  const payload =
    await request.json();

  const {
    event,
    data,
  } = payload;

  // ----------------------------------------------------------
  // SUCCESSFUL CHARGE
  // ----------------------------------------------------------

  if (
    event === "charge.completed" &&
    data?.status === "successful"
  ) {
    const userId =
      data?.meta?.userId;

    const planId =
      data?.meta?.planId;

    const planName =
      data?.meta?.planName ||
      "KreateBiz Pro";

    const interval =
      data?.meta?.interval ||
      "monthly";

    if (!userId) {
      console.warn(
        "Webhook received without userId."
      );

      return new Response(
        "OK",
        { status: 200 }
      );
    }

    const now = new Date();

    const expiresAt =
      new Date(now);

    if (
      interval.toLowerCase() ===
      "yearly"
    ) {
      expiresAt.setFullYear(
        expiresAt.getFullYear() + 1
      );
    } else {
      expiresAt.setMonth(
        expiresAt.getMonth() + 1
      );
    }

    let tier = "pro";

    if (
      planName
        .toLowerCase()
        .includes("business")
    ) {
      tier = "business";
    }

    // Subscription document
    await fsWrite(
      env,
      `subscriptions/${userId}`,
      {
        userId,

        planId:
          String(planId || ""),

        planName,

        tier,

        status: "active",

        startedAt: {
          __ts: true,
          value:
            now.toISOString(),
        },

        expiresAt: {
          __ts: true,
          value:
            expiresAt.toISOString(),
        },

        lastReference:
          data?.tx_ref || "",

        lastAmount:
          Number(data?.amount || 0),

        updatedAt: {
          __ts: true,
          value:
            now.toISOString(),
        },
      }
    );

    // User document
    await fsWrite(
      env,
      `users/${userId}`,
      {
        plan: tier,

        subscriptionStatus:
          "active",

        updatedAt: {
          __ts: true,
          value:
            now.toISOString(),
        },
      }
    );

    // Payment history
    await fsWrite(
      env,
      `payments/${data?.id || data?.tx_ref}`,
      {
        userId,

        email:
          data?.customer?.email ||
          "",

        amount:
          Number(data?.amount || 0),

        status:
          "successful",

        planName,

        reference:
          data?.tx_ref || "",

        createdAt: {
          __ts: true,
          value:
            now.toISOString(),
        },
      }
    );

    console.log(
      `Subscription activated: ${userId} → ${tier} until ${expiresAt.toISOString()}`
    );
  }

  // ----------------------------------------------------------
  // CANCELLED SUBSCRIPTION
  // ----------------------------------------------------------

  if (
    event ===
    "subscription.cancelled"
  ) {
    const userId =
      data?.meta?.userId;

    if (userId) {
      const now =
        new Date().toISOString();

      await fsWrite(
        env,
        `subscriptions/${userId}`,
        {
          status: "cancelled",

          updatedAt: {
            __ts: true,
            value: now,
          },
        }
      );

      await fsWrite(
        env,
        `users/${userId}`,
        {
          subscriptionStatus:
            "cancelled",

          updatedAt: {
            __ts: true,
            value: now,
          },
        }
      );
    }
  }

  return new Response(
    "OK",
    { status: 200 }
  );
}

// ============================================================
// ADMIN EXTEND
// ============================================================

async function adminExtend(
  request,
  env,
  cors
) {
  const {
    userId,
    days,
    adminEmail,
  } = await request.json();

  if (
    adminEmail !==
    env.ADMIN_EMAIL
  ) {
    return jsonResponse(
      {
        error: "Unauthorized",
      },
      403,
      cors
    );
  }

  const sub =
    await fsRead(
      env,
      `subscriptions/${userId}`
    );

  const current =
    sub?.expiresAt
      ? new Date(sub.expiresAt)
      : new Date();

  current.setDate(
    current.getDate() +
      Number(days)
  );

  const now =
    new Date().toISOString();

  await fsWrite(
    env,
    `subscriptions/${userId}`,
    {
      status: "active",

      expiresAt: {
        __ts: true,
        value:
          current.toISOString(),
      },

      updatedAt: {
        __ts: true,
        value: now,
      },
    }
  );

  await fsWrite(
    env,
    `users/${userId}`,
    {
      subscriptionStatus:
        "active",

      updatedAt: {
        __ts: true,
        value: now,
      },
    }
  );

  return jsonResponse(
    {
      ok: true,
      expiresAt:
        current.toISOString(),
    },
    200,
    cors
  );
}

// ============================================================
// ADMIN CANCEL
// ============================================================

async function adminCancel(
  request,
  env,
  cors
) {
  const {
    userId,
    adminEmail,
  } = await request.json();

  if (
    adminEmail !==
    env.ADMIN_EMAIL
  ) {
    return jsonResponse(
      {
        error: "Unauthorized",
      },
      403,
      cors
    );
  }

  const now =
    new Date().toISOString();

  await fsWrite(
    env,
    `subscriptions/${userId}`,
    {
      status: "cancelled",

      updatedAt: {
        __ts: true,
        value: now,
      },
    }
  );

  await fsWrite(
    env,
    `users/${userId}`,
    {
      plan: "free",

      subscriptionStatus:
        "cancelled",

      updatedAt: {
        __ts: true,
        value: now,
      },
    }
  );

  return jsonResponse(
    {
      ok: true,
    },
    200,
    cors
  );
    }

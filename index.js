const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

const OTP_TTL = 300;
const FREE_DAYS = 30;

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, "") || "/";

    try {
      if (path === "/" && request.method === "GET") {
        return json({ ok: true, service: "hesabdar-api", version: "1.0" });
      }
      if (path === "/send-otp" && request.method === "POST") {
        return await handleSendOtp(request, env);
      }
      if (path === "/verify-otp" && request.method === "POST") {
        return await handleVerifyOtp(request, env);
      }
      if (path === "/me" && request.method === "GET") {
        return await handleMe(request, env);
      }
      return json({ error: "not_found" }, 404);
    } catch (e) {
      return json({ error: "server_error", message: String(e.message || e) }, 500);
    }
  },
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS },
  });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function randomOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function randomToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function handleSendOtp(request, env) {
  const body = await request.json().catch(() => ({}));
  const email = normalizeEmail(body.email);

  if (!isValidEmail(email)) {
    return json({ error: "invalid_email" }, 400);
  }

  const rateKey = "otp_rate:" + email;
  if (await env.KV.get(rateKey)) {
    return json({ error: "too_many_requests", retry_after: 60 }, 429);
  }

  const code = randomOtp();
  await env.KV.put("otp:" + email, JSON.stringify({ code, created: Date.now() }), {
    expirationTtl: OTP_TTL,
  });
  await env.KV.put(rateKey, "1", { expirationTtl: 60 });

  if (!env.RESEND_API_KEY) {
    return json({ error: "email_not_configured" }, 500);
  }

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: "Bearer " + env.RESEND_API_KEY,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: "Hesabdar <onboarding@resend.dev>",
      to: [email],
      subject: "کد ورود دفتر مالی من",
      html:
        "<div style='font-family:Tahoma,sans-serif;direction:rtl;text-align:right'>" +
        "<h2>کد ورود شما</h2>" +
        "<p style='font-size:28px;letter-spacing:6px;font-weight:bold'>" +
        code +
        "</p><p>این کد تا ۵ دقیقه معتبر است.</p></div>",
    }),
  });

  if (!res.ok) {
    return json({ error: "email_send_failed", detail: await res.text() }, 502);
  }

  return json({ ok: true, message: "otp_sent" });
}

async function handleVerifyOtp(request, env) {
  const body = await request.json().catch(() => ({}));
  const email = normalizeEmail(body.email);
  const code = String(body.code || "").trim();
  const device = body.device || {};

  if (!isValidEmail(email) || !/^\d{6}$/.test(code)) {
    return json({ error: "invalid_input" }, 400);
  }

  const otpRaw = await env.KV.get("otp:" + email);
  if (!otpRaw) return json({ error: "otp_expired" }, 400);

  const otpData = JSON.parse(otpRaw);
  if (otpData.code !== code) return json({ error: "otp_invalid" }, 400);

  await env.KV.delete("otp:" + email);

  const userKey = "user:" + email;
  let user;
  const existing = await env.KV.get(userKey);
  if (existing) {
    user = JSON.parse(existing);
  } else {
    const now = Date.now();
    user = {
      email: email,
      created_at: now,
      free_until: now + FREE_DAYS * 24 * 60 * 60 * 1000,
      subscription_expiry: 0,
      subscription_plan: "",
      devices: [],
      name: body.name || "",
    };
  }

  const deviceId = await buildDeviceFingerprint(device);
  if (deviceId) {
    const already = user.devices.find(function (d) {
      return d.id === deviceId;
    });
    if (!already) {
      if (user.devices.length >= 3) {
        return json({ error: "device_limit_reached" }, 403);
      }
      user.devices.push({
        id: deviceId,
        model: device.model || "",
        brand: device.brand || "",
        android: device.android || "",
        bound_at: Date.now(),
      });
    }
  }

  await env.KV.put(userKey, JSON.stringify(user));
  if (deviceId) await env.KV.put("device:" + deviceId, email);

  const token = randomToken();
  await env.KV.put(
    "session:" + token,
    JSON.stringify({ email: email, deviceId: deviceId, created: Date.now() }),
    { expirationTtl: 60 * 60 * 24 * 90 }
  );

  return json({ ok: true, token: token, user: publicUser(user) });
}

async function handleMe(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return json({ error: "unauthorized" }, 401);

  const sessionRaw = await env.KV.get("session:" + token);
  if (!sessionRaw) return json({ error: "unauthorized" }, 401);

  const session = JSON.parse(sessionRaw);
  const userRaw = await env.KV.get("user:" + session.email);
  if (!userRaw) return json({ error: "user_not_found" }, 404);

  return json({ ok: true, user: publicUser(JSON.parse(userRaw)) });
}

async function buildDeviceFingerprint(device) {
  const parts = [
    device.android_id || "",
    device.serial || "",
    device.model || "",
    device.brand || "",
    device.android || "",
    device.install_id || "",
  ].join("|");
  if (!parts.replace(/\|/g, "")) return null;
  return await sha256(parts);
}

function publicUser(user) {
  const now = Date.now();
  return {
    email: user.email,
    name: user.name || "",
    free_until: user.free_until,
    subscription_expiry: user.subscription_expiry,
    subscription_plan: user.subscription_plan || "",
    access_active: user.free_until > now || user.subscription_expiry > now,
    devices_count: (user.devices || []).length,
  };
}
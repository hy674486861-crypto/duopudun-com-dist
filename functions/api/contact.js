const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
};

const FIELD_LIMITS = {
  name: 120,
  email: 254,
  company: 160,
  country: 120,
  whatsapp: 80,
  moq: 120,
  product: 240,
  message: 5000,
  pageLang: 24,
  pageUrl: 500,
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function clean(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function escapeHtml(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function validateFields(input) {
  const fields = {};
  for (const [key, limit] of Object.entries(FIELD_LIMITS)) {
    const value = clean(input[key]);
    if (value.length > limit) return null;
    fields[key] = value;
  }

  if (!fields.name || !fields.email || !fields.country || !fields.whatsapp || !fields.message) return null;
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(fields.email)) return null;
  return fields;
}

async function validateTurnstile(token, request, env) {
  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      secret: env.TURNSTILE_SECRET_KEY,
      response: token,
      remoteip: request.headers.get('CF-Connecting-IP') || undefined,
      idempotency_key: crypto.randomUUID(),
    }),
  });

  if (!response.ok) return false;
  const result = await response.json();
  return result.success === true && result.action === 'turnstile-spin-v2';
}

async function getZohoAccessToken(env) {
  const accountsUrl = (env.ZOHO_ACCOUNTS_URL || 'https://accounts.zoho.com').replace(/\/$/, '');
  const body = new URLSearchParams({
    client_id: env.ZOHO_CLIENT_ID,
    client_secret: env.ZOHO_CLIENT_SECRET,
    refresh_token: env.ZOHO_REFRESH_TOKEN,
    grant_type: 'refresh_token',
  });
  const response = await fetch(`${accountsUrl}/oauth/v2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });

  if (!response.ok) throw new Error(`Zoho token request failed: ${response.status}`);
  const result = await response.json();
  if (!result.access_token) throw new Error('Zoho token response did not include an access token');
  return result.access_token;
}

function buildEmail(fields) {
  const rows = [
    ['Name', fields.name],
    ['Email', fields.email],
    ['Company', fields.company || '-'],
    ['Country / Region', fields.country],
    ['WhatsApp', fields.whatsapp],
    ['Estimated quantity', fields.moq || '-'],
    ['Interested product', fields.product || '-'],
    ['Page language', fields.pageLang || '-'],
    ['Page URL', fields.pageUrl || '-'],
  ].map(([label, value]) => `<tr><th style="padding:8px 12px;text-align:left;background:#f2f7f4;border:1px solid #dce8e0">${label}</th><td style="padding:8px 12px;border:1px solid #dce8e0">${escapeHtml(value)}</td></tr>`).join('');

  return `
    <div style="font-family:Arial,sans-serif;color:#16231d;line-height:1.6">
      <h2 style="margin:0 0 16px;color:#0b7143">New Duopudun website inquiry</h2>
      <table style="border-collapse:collapse;width:100%;max-width:720px">${rows}</table>
      <h3 style="margin:24px 0 8px">Project requirements</h3>
      <div style="max-width:720px;padding:14px;background:#f7faf8;border-left:4px solid #16a267;white-space:pre-wrap">${escapeHtml(fields.message)}</div>
    </div>`;
}

export async function onRequestGet({ env }) {
  return json({ turnstileSiteKey: env.TURNSTILE_SITE_KEY || '' });
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
}

export async function onRequestPost({ request, env }) {
  const requiredSecrets = [
    'TURNSTILE_SITE_KEY',
    'TURNSTILE_SECRET_KEY',
    'ZOHO_CLIENT_ID',
    'ZOHO_CLIENT_SECRET',
    'ZOHO_REFRESH_TOKEN',
    'ZOHO_ACCOUNT_ID',
    'ZOHO_FROM_ADDRESS',
  ];
  if (requiredSecrets.some((key) => !env[key])) return json({ ok: false, error: 'service_unavailable' }, 503);

  const requestUrl = new URL(request.url);
  const origin = request.headers.get('Origin');
  if (origin && origin !== requestUrl.origin) return json({ ok: false, error: 'forbidden' }, 403);

  const contentLength = Number(request.headers.get('Content-Length') || 0);
  if (contentLength > 32_000) return json({ ok: false, error: 'payload_too_large' }, 413);

  let input;
  try {
    input = await request.json();
  } catch {
    return json({ ok: false, error: 'invalid_json' }, 400);
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return json({ ok: false, error: 'invalid_json' }, 400);
  }

  // Honeypot submissions receive a neutral response without sending mail.
  if (clean(input.website)) return json({ ok: true });

  const fields = validateFields(input);
  if (!fields) return json({ ok: false, error: 'invalid_fields' }, 400);

  const turnstileToken = clean(input.turnstileToken);
  if (!turnstileToken || !(await validateTurnstile(turnstileToken, request, env))) {
    return json({ ok: false, error: 'verification_failed' }, 400);
  }

  try {
    const accessToken = await getZohoAccessToken(env);
    const mailApiUrl = (env.ZOHO_MAIL_API_URL || 'https://mail.zoho.com').replace(/\/$/, '');
    const response = await fetch(`${mailApiUrl}/api/accounts/${encodeURIComponent(env.ZOHO_ACCOUNT_ID)}/messages`, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Authorization: `Zoho-oauthtoken ${accessToken}`,
      },
      body: JSON.stringify({
        fromAddress: env.ZOHO_FROM_ADDRESS,
        toAddress: env.CONTACT_TO_ADDRESS || 'Dexon@duopudun.com',
        subject: `[Website Inquiry] ${fields.name} - ${fields.product || fields.country}`,
        content: buildEmail(fields),
        mailFormat: 'html',
        encoding: 'UTF-8',
      }),
    });

    if (!response.ok) throw new Error(`Zoho send request failed: ${response.status}`);
    return json({ ok: true });
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'Contact form delivery failed');
    return json({ ok: false, error: 'delivery_failed' }, 502);
  }
}

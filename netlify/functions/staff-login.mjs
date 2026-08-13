import crypto from 'node:crypto';

const json = (statusCode, body) => ({
  statusCode,
  headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  },
  body: JSON.stringify(body),
});

function serverHeaders(secretKey) {
  const headers = {
    apikey: secretKey,
    'content-type': 'application/json',
  };
  // Legacy service_role keys are JWTs. New sb_secret_* keys must not be sent as Bearer JWTs.
  if (!secretKey.startsWith('sb_')) {
    headers.Authorization = `Bearer ${secretKey}`;
  }
  return headers;
}

export const handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  const supabaseUrl = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !secretKey) {
    return json(500, { error: 'Server login is not configured.' });
  }

  let payload;
  try { payload = JSON.parse(event.body || '{}'); }
  catch { return json(400, { error: 'Invalid request.' }); }

  const pin = String(payload.pin || '').trim();
  if (!/^\d{6}$/.test(pin)) return json(400, { error: 'Enter a 6-digit PIN.' });

  const forwarded = event.headers['x-forwarded-for'] || event.headers['client-ip'] || 'unknown';
  const ip = String(forwarded).split(',')[0].trim();
  const clientKey = crypto.createHmac('sha256', secretKey).update(ip).digest('hex');

  try {
    const rpcResp = await fetch(`${supabaseUrl}/rest/v1/rpc/verify_staff_pin_server`, {
      method: 'POST',
      headers: serverHeaders(secretKey),
      body: JSON.stringify({ p_pin: pin, p_client_key: clientKey }),
    });

    const rpcText = await rpcResp.text();
    let rows = null;
    try { rows = rpcText ? JSON.parse(rpcText) : null; } catch {}
    if (!rpcResp.ok) {
      console.error('PIN verifier error:', rpcResp.status, rpcText);
      return json(500, { error: 'Staff login is temporarily unavailable.' });
    }

    const result = Array.isArray(rows) ? rows[0] : rows;
    if (!result || result.status === 'invalid') return json(401, { error: 'Incorrect PIN.' });
    if (result.status === 'locked') return json(429, { error: 'Too many incorrect attempts. Try again in about 15 minutes.' });
    if (result.status !== 'ok' || !result.user_email) return json(401, { error: 'Incorrect PIN.' });

    const linkResp = await fetch(`${supabaseUrl}/auth/v1/admin/generate_link`, {
      method: 'POST',
      headers: serverHeaders(secretKey),
      body: JSON.stringify({ type: 'magiclink', email: result.user_email }),
    });

    const linkText = await linkResp.text();
    let linkData = null;
    try { linkData = linkText ? JSON.parse(linkText) : null; } catch {}
    if (!linkResp.ok || !linkData?.email_otp) {
      console.error('Session link error:', linkResp.status, linkText);
      return json(500, { error: 'Could not start the staff session.' });
    }

    return json(200, {
      email: result.user_email,
      role: result.staff_role,
      otp: linkData.email_otp,
    });
  } catch (err) {
    console.error('Staff login function error:', err);
    return json(500, { error: 'Staff login is temporarily unavailable.' });
  }
};

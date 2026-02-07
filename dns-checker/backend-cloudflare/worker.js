export default {
  async fetch(request, env) {
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Content-Type': 'application/json'
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    if (url.pathname === '/log' && request.method === 'POST') {
      return handleLog(request, env, corsHeaders);
    }

    if (url.pathname === '/stats' && request.method === 'GET') {
      return handleStats(request, env, corsHeaders);
    }

    return new Response(JSON.stringify({ error: 'Not found' }), {
      status: 404,
      headers: corsHeaders
    });
  }
};

async function handleLog(request, env, corsHeaders) {
  try {
    const data = await request.json();
    const { domain, results } = data;

    if (!domain || !results) {
      return new Response(JSON.stringify({ error: 'Missing required fields' }), {
        status: 400,
        headers: corsHeaders
      });
    }

    const timestamp = new Date().toISOString();
    const ipAddress = request.headers.get('CF-Connecting-IP') || 'unknown';
    const userAgent = request.headers.get('User-Agent') || 'unknown';

    await env.DB.prepare(
      `INSERT INTO audit_log (domain, timestamp, ip_address, user_agent, spf_exists, spf_record, dkim_bh, dkim_ba, dkim_ba2, dkim_hf, dkim_hf2, dmarc_exists, dmarc_policy)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      domain,
      timestamp,
      ipAddress,
      userAgent,
      results.spf?.hasExactlyOne ? 1 : 0,
      results.spf?.record || null,
      results.dkim?.bh ? 1 : 0,
      results.dkim?.ba ? 1 : 0,
      results.dkim?.ba2 ? 1 : 0,
      results.dkim?.hf ? 1 : 0,
      results.dkim?.hf2 ? 1 : 0,
      results.dmarc?.exists ? 1 : 0,
      results.dmarc?.policy || null
    ).run();

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: corsHeaders
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: corsHeaders
    });
  }
}

async function handleStats(request, env, corsHeaders) {
  try {
    const topDomains = await env.DB.prepare(
      `SELECT domain, COUNT(*) as count 
       FROM audit_log 
       GROUP BY domain 
       ORDER BY count DESC 
       LIMIT 10`
    ).all();

    const recentChecks = await env.DB.prepare(
      `SELECT domain, timestamp 
       FROM audit_log 
       ORDER BY timestamp DESC 
       LIMIT 20`
    ).all();

    const totalChecks = await env.DB.prepare(
      `SELECT COUNT(*) as total FROM audit_log`
    ).first();

    return new Response(JSON.stringify({
      topDomains: topDomains.results,
      recentChecks: recentChecks.results,
      totalChecks: totalChecks.total
    }), {
      status: 200,
      headers: corsHeaders
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: corsHeaders
    });
  }
}

# Cloudflare Workers Backend Setup

## Prerequisites
1. Cloudflare account (free tier works)
2. Node.js installed
3. npm or yarn

## Setup Steps

### 1. Install Wrangler CLI
```bash
npm install -g wrangler
```

### 2. Login to Cloudflare
```bash
wrangler login
```

### 3. Create D1 Database
```bash
wrangler d1 create dns-checker-db
```

This will output a database ID. Copy it and update `wrangler.toml`:
```toml
database_id = "YOUR_DATABASE_ID_HERE"
```

### 4. Initialize Database Schema
```bash
wrangler d1 execute dns-checker-db --file=schema.sql
```

### 5. Deploy Worker
```bash
wrangler deploy
```

The deployment will give you a worker URL like:
`https://dns-checker-api.YOUR-SUBDOMAIN.workers.dev`

### 6. Update Frontend

In your `app.js`, add after the `displayResults()` call:

```javascript
async function logAudit(domain, spfResult, dkimResults, dmarcResult) {
  try {
    await fetch('https://dns-checker-api.YOUR-SUBDOMAIN.workers.dev/log', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        domain,
        results: {
          spf: spfResult,
          dkim: dkimResults,
          dmarc: dmarcResult
        }
      })
    });
  } catch (error) {
    console.error('Audit logging failed:', error);
  }
}
```

Then call it in `handleCheck()` after `displayResults()`:
```javascript
displayResults(spfResult, dkimResults, dmarcResult);
await logAudit(domain, spfResult, dkimResults, dmarcResult);
```

## Testing Locally

```bash
wrangler dev
```

Test with curl:
```bash
curl -X POST http://localhost:8787/log \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","results":{"spf":{"hasExactlyOne":true},"dkim":{},"dmarc":{}}}'
```

## View Stats

Access stats endpoint:
```
https://dns-checker-api.YOUR-SUBDOMAIN.workers.dev/stats
```

## Manage Database

Query database:
```bash
wrangler d1 execute dns-checker-db --command="SELECT * FROM audit_log LIMIT 10"
```

Delete old records:
```bash
wrangler d1 execute dns-checker-db --command="DELETE FROM audit_log WHERE timestamp < datetime('now', '-90 days')"
```

## Cost
- Free tier: 100,000 requests/day
- D1 database: Free up to 5GB storage
- Perfect for expo usage

## Monitoring

View logs:
```bash
wrangler tail
```

## Production Considerations

1. **Rate Limiting**: Add rate limiting to prevent abuse
2. **Authentication**: Add API key for stats endpoint
3. **Data Retention**: Set up scheduled cleanup (90 days)
4. **Privacy**: Add privacy notice to frontend
5. **GDPR**: Hash IP addresses if needed

## Optional: Create Stats Dashboard

Create `stats.html` in your main project to visualize data.

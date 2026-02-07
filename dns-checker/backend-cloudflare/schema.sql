CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  spf_exists INTEGER,
  spf_record TEXT,
  dkim_bh INTEGER,
  dkim_ba INTEGER,
  dkim_ba2 INTEGER,
  dkim_hf INTEGER,
  dkim_hf2 INTEGER,
  dmarc_exists INTEGER,
  dmarc_policy TEXT
);

CREATE INDEX IF NOT EXISTS idx_domain ON audit_log(domain);
CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_ip_address ON audit_log(ip_address);

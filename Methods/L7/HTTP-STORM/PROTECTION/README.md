# Protection Guides

This directory contains protection guides and defense strategies for the TORNADO HTTP/2 Load Testing Tool (http-storm.js).

## Available Guides

### Comprehensive Protection Guide

**File:** `PROTECTION_GUIDE.md`

Comprehensive guide explaining how to implement multi-layer protection against HTTP/2 and HTTP/1.1 flood attacks.

**Topics covered:**
- HTTP/2 attack signatures identification
- HTTP/1.1 attack patterns
- Rate limiting strategies (Nginx, Apache, Application-level)
- WAF rules (Cloudflare, AWS WAF, ModSecurity)
- Application-level protections (Node.js, Express, Python)
- Monitoring and alerting
- CDN protection (Cloudflare, AWS Shield)
- Advanced detection techniques
- Complete protection scripts

## Protection Strategies

### 1. Multi-Layer Defense Approach

Effective HTTP flood protection requires **multiple layers** of defense:

```
┌─────────────────────────────────────────┐
│  Layer 1: CDN/DDoS Protection Service   │
│  - Cloudflare, AWS Shield               │
│  - Rate limiting at edge                │
│  - Bot detection                        │
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│  Layer 2: Web Server Rate Limiting     │
│  - Nginx limit_req                      │
│  - Apache mod_evasive                   │
│  - Connection limiting                  │
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│  Layer 3: WAF (Web Application Firewall)│
│  - ModSecurity rules                    │
│  - Cloudflare WAF                       │
│  - AWS WAF                              │
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│  Layer 4: Application-Level Protection  │
│  - Express rate limiting                │
│  - Request validation                   │
│  - IP whitelisting/blacklisting         │
└─────────────────────────────────────────┘
```

### 2. Rate Limiting (Primary Defense)

The most effective method for HTTP floods - limits requests per second:

- **Legitimate traffic:** ~10-100 req/sec per IP
- **Attack traffic:** 50k-200k+ req/sec total
- **Recommended limit:** 20-50 req/sec per IP

### 3. HTTP/2 Signature Detection

Identifies and blocks requests matching specific attack signatures:

- **HTTP/2 Settings Patterns** - Specific SETTINGS frame values
- **Header Table Size** - Unusual header table sizes (65535-65537)
- **Window Size** - Specific window update values (15663105)
- **Stream ID Patterns** - Sequential stream IDs (1, 3, 5, 7...)
- **HPACK Patterns** - Specific header compression patterns

### 4. Header Pattern Detection

Identifies consistent header patterns from automated tools:

- **User-Agent Patterns** - Repeated user-agent strings
- **Header Order** - Consistent header ordering
- **Missing Headers** - Absence of expected headers
- **Custom Header Patterns** - Suspicious custom headers

### 5. Proxy IP Detection

Blocks known proxy IP addresses used in attacks.

## Quick Protection Setup

### Nginx Rate Limiting

```nginx
# Define rate limit zones
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=20r/s;
limit_req_zone $binary_remote_addr zone=general_limit:10m rate=50r/s;

# Apply to API endpoints
location /api/ {
    limit_req zone=api_limit burst=30 nodelay;
    limit_req_status 429;
    # ... rest of config
}

# Apply to general pages
location / {
    limit_req zone=general_limit burst=50 nodelay;
    limit_req_status 429;
    # ... rest of config
}
```

### Application-Level (Express.js)

```javascript
const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', apiLimiter);
```

### Cloudflare WAF Rules

```javascript
// Rate limiting rule
(http.request.uri.path matches "^/api/") and 
(http.request.rate.ge(100)) 
-> Block

// HTTP/2 settings detection
(http.request.protocol eq "HTTP/2") and
(http.request.headers["x-custom-header"] exists)
-> Challenge
```

For detailed protection guides, see `PROTECTION_GUIDE.md`.


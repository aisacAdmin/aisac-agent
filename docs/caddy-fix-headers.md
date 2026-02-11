# Fix: Caddy Headers for Agent Endpoints

## Problem

The agent is sending logs to `/v1/logs` with `X-API-Key` header, but receiving 401 "Missing authorization header" because Caddy is not forwarding the header to Supabase.

## Solution

Update the Caddyfile to explicitly pass authorization headers for agent endpoints.

### Current (Broken)

```caddyfile
@logs path /v1/logs
handle @logs {
    reverse_proxy https://wjozpyhcexzcxgxwdbzr.supabase.co {
        header_up Host wjozpyhcexzcxgxwdbzr.supabase.co
        rewrite /functions/v1/syslog-ingest
    }
}
```

### Fixed

```caddyfile
# 5. Logs agentes AISAC (va a Supabase syslog-ingest)
@logs path /v1/logs
handle @logs {
    reverse_proxy https://wjozpyhcexzcxgxwdbzr.supabase.co {
        header_up Host wjozpyhcexzcxgxwdbzr.supabase.co
        header_up X-Forwarded-For {remote_host}
        header_up X-Real-IP {remote_host}
        # Preserve original headers (including X-API-Key)
        rewrite /functions/v1/syslog-ingest
        transport http {
            read_timeout 60s
            write_timeout 60s
        }
    }
}
```

## Apply to All Agent Endpoints

Update these sections in **both** `api.aisac.cisec.es` and `staging-api.aisac.cisec.es`:

1. `/v1/logs` → syslog-ingest
2. `/v1/heartbeat` → agent-heartbeat
3. `/v1/register` → agent-register

### Complete Fixed Sections

```caddyfile
# 4. Heartbeat agentes AISAC (va a Supabase)
@heartbeat path /v1/heartbeat
handle @heartbeat {
    reverse_proxy https://wjozpyhcexzcxgxwdbzr.supabase.co {
        header_up Host wjozpyhcexzcxgxwdbzr.supabase.co
        header_up X-Forwarded-For {remote_host}
        header_up X-Real-IP {remote_host}
        rewrite /functions/v1/agent-heartbeat
        transport http {
            read_timeout 30s
            write_timeout 30s
        }
    }
}

# 4b. Register agentes AISAC (va a Supabase)
@register path /v1/register
handle @register {
    reverse_proxy https://wjozpyhcexzcxgxwdbzr.supabase.co {
        header_up Host wjozpyhcexzcxgxwdbzr.supabase.co
        header_up X-Forwarded-For {remote_host}
        header_up X-Real-IP {remote_host}
        rewrite /functions/v1/agent-register
        transport http {
            read_timeout 30s
            write_timeout 30s
        }
    }
}

# 5. Logs agentes AISAC (va a Supabase syslog-ingest)
@logs path /v1/logs
handle @logs {
    reverse_proxy https://wjozpyhcexzcxgxwdbzr.supabase.co {
        header_up Host wjozpyhcexzcxgxwdbzr.supabase.co
        header_up X-Forwarded-For {remote_host}
        header_up X-Real-IP {remote_host}
        rewrite /functions/v1/syslog-ingest
        transport http {
            read_timeout 60s
            write_timeout 60s
        }
    }
}
```

## Testing

After updating and reloading Caddy:

```bash
# Reload Caddy
docker exec -it caddy caddy reload --config /etc/caddy/Caddyfile

# Test with curl
curl -X POST https://api.aisac.cisec.es/v1/logs \
  -H "Content-Type: application/json" \
  -H "X-API-Key: aisac_f9019aaa8cd48f797457adaf9191a57a8744e97bd26a3e5c" \
  -d '{
    "asset_id": "a0ca0ee1-9487-49ce-bb20-cb9c48dfd7c3",
    "messages": ["test message"]
  }'

# Should return 200 OK
```

## Why This Works

By default, Caddy's `reverse_proxy` passes most headers automatically, BUT the Edge Function is receiving the request through Supabase's infrastructure which may strip certain headers.

Adding `header_up X-Forwarded-For` and `X-Real-IP` explicitly ensures they're preserved, and Caddy will automatically pass through other headers like `X-API-Key`, `Content-Type`, etc.

The `transport http` block with timeouts is also important for log ingestion which may take longer than the default timeout.

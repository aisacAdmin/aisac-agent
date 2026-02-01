# AISAC Supabase Edge Functions

Edge Functions para recibir datos de los agentes AISAC.

## Funciones

| Función | Descripción |
|---------|-------------|
| `agent-heartbeat` | Recibe heartbeats de agentes, actualiza estado del asset |
| `syslog-ingest` | Recibe eventos de logs del collector |

## Esquema de Base de Datos

**IMPORTANTE:** El API Key se almacena en `monitored_assets.api_key` (NO en tabla separada).

### Validación de API Key

```sql
-- Usando función RPC
SELECT * FROM validate_asset_api_key('aisac_xxxx...');

-- O query directo
SELECT id, tenant_id, name FROM monitored_assets
WHERE api_key = 'aisac_xxxx...'
  AND ingestion_enabled = true;
```

## Despliegue

```bash
# Instalar Supabase CLI
brew install supabase/tap/supabase

# Login y vincular proyecto
supabase login
supabase link --project-ref YOUR_PROJECT_REF

# Desplegar funciones
supabase functions deploy agent-heartbeat
supabase functions deploy syslog-ingest
```

## Endpoints

### POST /functions/v1/agent-heartbeat

```bash
curl -X POST 'https://YOUR_PROJECT.supabase.co/functions/v1/agent-heartbeat' \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: aisac_xxxx...' \
  -d '{
    "asset_id": "uuid-here",
    "timestamp": "2024-01-15T10:30:00Z",
    "agent_version": "1.0.0",
    "metrics": {"cpu_percent": 10, "memory_percent": 50, "disk_percent": 30, "uptime_seconds": 3600}
  }'
```

### POST /functions/v1/syslog-ingest

```bash
curl -X POST 'https://YOUR_PROJECT.supabase.co/functions/v1/syslog-ingest' \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: aisac_xxxx...' \
  -d '{
    "events": [
      {"@timestamp": "2024-01-15T10:30:00Z", "source": "suricata", "host": "server1", "fields": {}}
    ]
  }'
```

## Ver Logs

```bash
supabase functions logs agent-heartbeat --project-ref YOUR_PROJECT_REF
supabase functions logs syslog-ingest --project-ref YOUR_PROJECT_REF
```

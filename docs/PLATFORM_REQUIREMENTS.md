# Requisitos para el Equipo de Plataforma AISAC

## Problema Actual

El agente AISAC instalado en el servidor `n8n` está recibiendo **error 401 (Unauthorized)** al intentar enviar heartbeats a la plataforma.

```
Error del agente:
{"level":"error","component":"heartbeat","status":401,"message":"Heartbeat unauthorized - invalid API Key, stopping heartbeat"}
```

**Configuración del agente:**
- API Key: `aisac_9ded1557a711b99682995852702d30c2b1a3070863f7ae53`
- Asset ID: `d2a84f77-207e-4fb6-8860-09502b09db78`
- URL Heartbeat: `https://api.aisac.cisec.es/v1/heartbeat`
- URL Syslog: `https://api.aisac.cisec.es/v1/logs`

---

## Esquema de Base de Datos (Confirmado)

El API Key se almacena en `monitored_assets.api_key` (NO en una tabla `api_keys` separada).

### Validación de API Key

**Opción 1 - Usando función RPC existente:**
```sql
SELECT * FROM validate_asset_api_key('aisac_9ded1557a711b99682995852702d30c2b1a3070863f7ae53');
```
Retorna:
```json
{
  "asset_id": "uuid",
  "tenant_id": "uuid",
  "asset_name": "nombre del asset",
  "is_valid": true/false
}
```

**Opción 2 - Query directo:**
```sql
SELECT id, tenant_id, name, ingestion_enabled, status
FROM monitored_assets
WHERE api_key = 'aisac_9ded1557a711b99682995852702d30c2b1a3070863f7ae53'
  AND ingestion_enabled = true
  AND status != 'decommissioned';
```

---

## Edge Functions Requeridas

### 1. `agent-heartbeat`

**Endpoint:** `POST /v1/heartbeat`

**Headers:**
```
Content-Type: application/json
X-API-Key: aisac_xxxxxxxxxxxx
```

**Body:**
```json
{
  "asset_id": "d2a84f77-207e-4fb6-8860-09502b09db78",
  "timestamp": "2024-01-15T10:30:00Z",
  "agent_version": "1.0.0",
  "metrics": {
    "cpu_percent": 25.5,
    "memory_percent": 60.2,
    "disk_percent": 45.0,
    "uptime_seconds": 86400
  }
}
```

**Lógica:**
```typescript
// Validar API Key contra monitored_assets
const { data: asset, error } = await supabase
  .from('monitored_assets')
  .select('id, tenant_id, name, criticality, ingestion_enabled, status')
  .eq('id', payload.asset_id)
  .eq('api_key', apiKey)
  .single();
```

**Respuesta esperada (200 OK):**
```json
{
  "success": true,
  "next_heartbeat_in": 120,
  "message": "Heartbeat received"
}
```

---

### 2. `syslog-ingest`

**Endpoint:** `POST /v1/logs`

**Headers:**
```
Content-Type: application/json
X-API-Key: aisac_xxxxxxxxxxxx
```

**Lógica:**
```typescript
// Validar usando RPC
const { data: validation } = await supabase
  .rpc('validate_asset_api_key', { p_api_key: apiKey });
```

**Respuesta esperada (200 OK):**
```json
{
  "success": true,
  "received": 100,
  "stored": 100,
  "message": "Successfully stored 100 events"
}
```

---

## Código de las Edge Functions

El código actualizado está en:
- `supabase/functions/agent-heartbeat/index.ts`
- `supabase/functions/syslog-ingest/index.ts`

Desplegar con:
```bash
supabase functions deploy agent-heartbeat
supabase functions deploy syslog-ingest
```

---

## Checklist

- [ ] Verificar que la API Key `aisac_9ded1557...` existe en `monitored_assets.api_key`
- [ ] Verificar que el asset tiene `ingestion_enabled = true`
- [ ] Verificar que el asset tiene `status != 'decommissioned'`
- [ ] Verificar que la función RPC `validate_asset_api_key` existe
- [ ] Desplegar Edge Function `agent-heartbeat` actualizada
- [ ] Desplegar Edge Function `syslog-ingest` actualizada
- [ ] Verificar que el proxy Caddy redirige a Supabase

### Test manual:

```bash
curl -v -X POST 'https://api.aisac.cisec.es/v1/heartbeat' \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: aisac_9ded1557a711b99682995852702d30c2b1a3070863f7ae53' \
  -d '{
    "asset_id": "d2a84f77-207e-4fb6-8860-09502b09db78",
    "timestamp": "2024-01-15T10:30:00Z",
    "agent_version": "1.0.0",
    "metrics": {"cpu_percent": 10, "memory_percent": 50, "disk_percent": 30, "uptime_seconds": 3600}
  }'
```

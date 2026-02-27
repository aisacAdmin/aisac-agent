# Especificación de Edge Functions para AISAC Agent

## Contexto

El **AISAC Agent** es un agente instalado en servidores que envía:
1. **Heartbeats** periódicos (estado del servidor, métricas)
2. **Logs de seguridad** (Suricata, Wazuh, syslog)

El agente ya está instalado y funcionando, pero recibe **401 Unauthorized** porque las Edge Functions no existen o no validan correctamente el API Key.

---

## Endpoints Requeridos

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/v1/heartbeat` | POST | Recibe heartbeats de agentes |
| `/v1/logs` | POST | Recibe batches de eventos de logs |

---

## 1. Edge Function: `agent-heartbeat`

### Request

```http
POST /v1/heartbeat
Content-Type: application/json
X-API-Key: aisac_9ded1557a711b99682995852702d30c2b1a3070863f7ae53
```

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

### Lógica de la función

```typescript
// 1. Extraer API Key del header
const apiKey = req.headers.get("X-API-Key");

// 2. Validar formato (aisac_ + 48 caracteres hex = 54 total)
if (!apiKey?.startsWith("aisac_") || apiKey.length !== 54) {
  return error(401, "Invalid API Key format");
}

// 3. Parsear body
const { asset_id, timestamp, agent_version, metrics } = await req.json();

// 4. Validar API Key contra monitored_assets
const { data: asset, error } = await supabase
  .from("monitored_assets")
  .select("id, tenant_id, name, ingestion_enabled, status")
  .eq("id", asset_id)
  .eq("api_key", apiKey)
  .single();

if (error || !asset) {
  return error(401, "Invalid API Key or asset not found");
}

// 5. Verificar que el asset está habilitado
if (!asset.ingestion_enabled || asset.status === "decommissioned") {
  return error(403, "Asset is disabled");
}

// 6. Actualizar estado del asset
await supabase
  .from("monitored_assets")
  .update({
    status: "online",
    last_seen_at: new Date().toISOString(),
    agent_version: agent_version,
    metrics: metrics  // JSONB column
  })
  .eq("id", asset_id);

// 7. Retornar respuesta
return {
  success: true,
  next_heartbeat_in: 120,  // segundos hasta próximo heartbeat
  message: "Heartbeat received"
};
```

### Response (200 OK)

```json
{
  "success": true,
  "next_heartbeat_in": 120,
  "message": "Heartbeat received"
}
```

### Response (401 Unauthorized)

```json
{
  "success": false,
  "message": "Invalid API Key or asset not found"
}
```

---

## 2. Edge Function: `syslog-ingest`

### Request

```http
POST /v1/logs
Content-Type: application/json
X-API-Key: aisac_9ded1557a711b99682995852702d30c2b1a3070863f7ae53
```

```json
{
  "events": [
    {
      "@timestamp": "2024-01-15T10:30:00.123Z",
      "source": "suricata",
      "host": "n8n",
      "message": "ET SCAN Potential SSH Scan",
      "fields": {
        "event_type": "alert",
        "src_ip": "192.168.1.100",
        "src_port": 45678,
        "dest_ip": "10.0.0.1",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
          "signature": "ET SCAN Potential SSH Scan",
          "signature_id": 2001219,
          "severity": 2,
          "category": "Attempted Information Leak"
        }
      }
    }
  ]
}
```

### Lógica de la función

```typescript
// 1. Extraer API Key (soporta ambos headers)
const apiKey = req.headers.get("X-API-Key")
  || req.headers.get("Authorization")?.replace("Bearer ", "");

// 2. Validar formato
if (!apiKey?.startsWith("aisac_") || apiKey.length !== 54) {
  return error(401, "Invalid API Key format");
}

// 3. Parsear body
const { events } = await req.json();

if (!Array.isArray(events) || events.length === 0) {
  return { success: true, received: 0, stored: 0 };
}

// 4. Validar API Key usando función RPC existente
const { data: validation } = await supabase
  .rpc("validate_asset_api_key", { p_api_key: apiKey });

if (!validation?.is_valid) {
  return error(401, "Invalid API Key");
}

const { asset_id, tenant_id } = validation;

// 5. Preparar eventos para inserción
const eventsToInsert = events.map(event => ({
  tenant_id: tenant_id,
  monitored_asset_id: asset_id,
  timestamp: event["@timestamp"] || new Date().toISOString(),
  source: event.source,
  host: event.host,
  message: event.message,
  fields: event.fields,
  raw_event: event
}));

// 6. Insertar en tabla de logs (ajustar nombre de tabla según esquema)
const { data, error } = await supabase
  .from("log_events")  // o "syslog_events" según el esquema
  .insert(eventsToInsert)
  .select("id");

// 7. Actualizar último log recibido en el asset
await supabase
  .from("monitored_assets")
  .update({ last_log_at: new Date().toISOString() })
  .eq("id", asset_id);

// 8. Retornar respuesta
return {
  success: true,
  received: events.length,
  stored: data?.length || 0,
  message: `Successfully stored ${data?.length || 0} events`
};
```

### Response (200 OK)

```json
{
  "success": true,
  "received": 100,
  "stored": 100,
  "message": "Successfully stored 100 events"
}
```

---

## Esquema de Base de Datos Requerido

### Columnas en `monitored_assets`

```sql
-- Verificar que existen estas columnas
ALTER TABLE monitored_assets
ADD COLUMN IF NOT EXISTS api_key TEXT UNIQUE,
ADD COLUMN IF NOT EXISTS agent_version TEXT,
ADD COLUMN IF NOT EXISTS metrics JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS last_log_at TIMESTAMPTZ;

-- Índice para búsqueda por API Key
CREATE INDEX IF NOT EXISTS idx_monitored_assets_api_key
ON monitored_assets(api_key) WHERE api_key IS NOT NULL;
```

### Tabla para logs (si no existe)

```sql
CREATE TABLE IF NOT EXISTS log_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  monitored_asset_id UUID,
  timestamp TIMESTAMPTZ NOT NULL,
  source TEXT NOT NULL,
  host TEXT,
  message TEXT,
  fields JSONB DEFAULT '{}',
  raw_event JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Índices para queries
CREATE INDEX idx_log_events_tenant_timestamp
ON log_events(tenant_id, timestamp DESC);

CREATE INDEX idx_log_events_asset
ON log_events(monitored_asset_id, timestamp DESC);
```

### Función RPC `validate_asset_api_key`

Si no existe, crear:

```sql
CREATE OR REPLACE FUNCTION validate_asset_api_key(p_api_key TEXT)
RETURNS JSON AS $$
DECLARE
  v_asset RECORD;
BEGIN
  SELECT id, tenant_id, name, ingestion_enabled, status
  INTO v_asset
  FROM monitored_assets
  WHERE api_key = p_api_key
    AND ingestion_enabled = true
    AND status != 'decommissioned'
  LIMIT 1;

  IF v_asset IS NULL THEN
    RETURN json_build_object(
      'is_valid', false,
      'message', 'API Key not found or asset disabled'
    );
  END IF;

  RETURN json_build_object(
    'is_valid', true,
    'asset_id', v_asset.id,
    'tenant_id', v_asset.tenant_id,
    'asset_name', v_asset.name
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

---

## Verificación Rápida

### 1. Verificar que el API Key existe

```sql
SELECT id, name, api_key, ingestion_enabled, status
FROM monitored_assets
WHERE api_key = 'aisac_9ded1557a711b99682995852702d30c2b1a3070863f7ae53';
```

**Debe retornar 1 fila** con:
- `ingestion_enabled = true`
- `status != 'decommissioned'`

### 2. Probar función RPC

```sql
SELECT validate_asset_api_key('aisac_9ded1557a711b99682995852702d30c2b1a3070863f7ae53');
```

**Debe retornar:**
```json
{"is_valid": true, "asset_id": "d2a84f77-...", "tenant_id": "...", "asset_name": "..."}
```

### 3. Test de endpoint después de desplegar

```bash
curl -X POST 'https://api.aisac.cisec.es/v1/heartbeat' \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: aisac_9ded1557a711b99682995852702d30c2b1a3070863f7ae53' \
  -d '{
    "asset_id": "d2a84f77-207e-4fb6-8860-09502b09db78",
    "timestamp": "2024-01-15T10:30:00Z",
    "agent_version": "1.0.0",
    "metrics": {"cpu_percent": 10}
  }'
```

**Debe retornar 200 OK:**
```json
{"success": true, "next_heartbeat_in": 120, "message": "Heartbeat received"}
```

---

## Configuración del Proxy Caddy

Si `api.aisac.cisec.es` es un reverse proxy:

```
api.aisac.cisec.es {
    reverse_proxy /functions/v1/* https://YOUR_SUPABASE_PROJECT.supabase.co {
        header_up Host YOUR_SUPABASE_PROJECT.supabase.co
    }
}
```

---

## Resumen de Tareas

1. **Verificar** que la API Key existe en `monitored_assets.api_key`
2. **Verificar/crear** función RPC `validate_asset_api_key`
3. **Verificar/crear** tabla `log_events` para almacenar logs
4. **Desarrollar** Edge Function `agent-heartbeat`
5. **Desarrollar** Edge Function `syslog-ingest`
6. **Desplegar** ambas funciones
7. **Verificar** que el proxy Caddy redirige correctamente
8. **Probar** con el curl de ejemplo

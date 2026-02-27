# Guia de Instalacion - AISAC Agent

Guia paso a paso para instalar el agente AISAC en servidores Linux y Windows.

## Indice

1. [Requisitos previos](#1-requisitos-previos)
2. [Obtener credenciales de la plataforma](#2-obtener-credenciales-de-la-plataforma)
3. [Instalacion en Linux](#3-instalacion-en-linux)
4. [Instalacion en Windows](#4-instalacion-en-windows)
5. [Instalacion no interactiva](#5-instalacion-no-interactiva)
6. [Verificacion post-instalacion](#6-verificacion-post-instalacion)
7. [Modos de operacion](#7-modos-de-operacion)
8. [Dependencias opcionales](#8-dependencias-opcionales)
9. [Desinstalacion](#9-desinstalacion)
10. [Referencia de variables de entorno](#10-referencia-de-variables-de-entorno)
11. [Resolucion de problemas](#11-resolucion-de-problemas)

---

## 1. Requisitos previos

### Requisitos del sistema

| Requisito | Linux | Windows |
|-----------|-------|---------|
| Acceso | root / sudo | Administrador |
| Init system | systemd | Windows Services (sc.exe) |
| Shell | bash | PowerShell 3.0+ |
| Descarga | curl o wget | PowerShell (Invoke-WebRequest) |
| Certificados (solo SOAR) | openssl | openssl ([descargar](https://slproweb.com/products/Win32OpenSSL.html)) |

### Arquitecturas soportadas

- **Linux**: amd64 (x86_64), arm64 (aarch64)
- **Windows**: amd64

### Conectividad de red

El agente necesita acceso HTTPS (puerto 443) a:

| Endpoint | Uso |
|----------|-----|
| `api.aisac.cisec.es` | Registro, heartbeat e ingesta de logs |
| Command Server (puerto 8443) | Solo si SOAR esta habilitado |

---

## 2. Obtener credenciales de la plataforma

Antes de instalar, necesitas obtener dos datos del dashboard de AISAC:

1. **API Key** - Formato: `aisac_xxxx...`
   - Dashboard > Assets > [Tu asset] > API Key

2. **Asset ID** - Formato: UUID (`550e8400-e29b-41d4-a716-446655440000`)
   - Dashboard > Assets > [Tu asset] > ID

> **Nota**: El asset debe existir previamente en la plataforma. El instalador no crea assets nuevos, solo registra el agente contra un asset existente.

Si ademas vas a usar **SOAR** (respuesta automatizada a incidentes), necesitaras:

3. **Command Server token** - Se genera durante la instalacion o se proporciona manualmente
4. **Command Server URL** - URL publica del Command Server (ej: `https://tu-servidor:8443`)

---

## 3. Instalacion en Linux

### Paso 1: Descargar el instalador

```bash
# Clonar el repositorio
git clone https://github.com/CISECSL/aisac-agent.git
cd aisac-agent
```

O descargar solo el script:

```bash
curl -sSLO https://raw.githubusercontent.com/CISECSL/aisac-agent/main/scripts/install.sh
chmod +x install.sh
```

### Paso 2: Ejecutar el instalador

```bash
sudo ./scripts/install.sh
```

El instalador guiara paso a paso por la configuracion:

#### Paso 2.1: Credenciales de la plataforma

```
--- Step 1: AISAC Platform Credentials ---

Enter your AISAC API Key (format: aisac_xxxx...): aisac_tu_api_key
Enter your Asset ID (UUID from platform): 550e8400-e29b-41d4-...
```

#### Paso 2.2: Agent ID

Se genera automaticamente con formato `agent-{hostname}-{random}`.
Si ya existe una instalacion previa, se reutiliza el ID anterior.

#### Paso 2.3: Configuracion SOAR (opcional)

```
--- Step 3: SOAR Configuration (Command Server) ---

Enable SOAR response capabilities? [y/N]: y
Install Command Server on this machine? [Y/n]: y
```

Si se habilita SOAR:
- Se instala el Command Server como servicio systemd
- Se generan certificados mTLS (CA + agente + servidor)
- Se solicita la URL publica del Command Server

#### Paso 2.4: Colector de logs (opcional)

```
--- Step 4: Log Collector Configuration (SIEM) ---

Enable log collection? [Y/n]: y
```

El instalador auto-detecta fuentes de logs disponibles:
- **Suricata** en `/var/log/suricata/eve.json`
- **Wazuh** en `/var/ossec/logs/alerts/alerts.json`
- **Syslog** en `/var/log/syslog` o `/var/log/messages`

#### Paso 2.5: Heartbeat

```
--- Step 5: Heartbeat Configuration ---

Enable heartbeat reporting? [Y/n]: y
```

#### Paso 2.6: Registro y arranque

El instalador:
1. Compila los binarios (si Go esta disponible) o descarga de GitHub Releases
2. Crea los directorios necesarios
3. Genera el fichero de configuracion `/etc/aisac/agent.yaml`
4. Registra el agente en la plataforma
5. Instala y arranca los servicios systemd

### Estructura de directorios resultante

```
/opt/aisac/
  aisac-agent              # Binario del agente
  aisac-server             # Binario del Command Server (si SOAR)
/etc/aisac/
  agent.yaml               # Configuracion
  certs/                   # Certificados mTLS (si SOAR)
    ca.crt, agent.crt, agent.key, server.crt, server.key
  server-api-token         # Token del CS (si SOAR)
/var/lib/aisac/
  agent-id                 # ID persistente del agente
  sincedb.json             # Posiciones de lectura de logs
  safety_state.json        # Estado de acciones SOAR activas
/var/log/aisac/
  agent.log                # Logs del agente
```

---

## 4. Instalacion en Windows

### Paso 1: Descargar el instalador

```powershell
git clone https://github.com/CISECSL/aisac-agent.git
cd aisac-agent
```

### Paso 2: Ejecutar el instalador

Abrir PowerShell **como Administrador**:

```powershell
.\scripts\install.ps1
```

El flujo interactivo es identico al de Linux. Las diferencias son:

| Concepto | Linux | Windows |
|----------|-------|---------|
| Binarios | `/opt/aisac/` | `C:\Program Files\AISAC\` |
| Configuracion | `/etc/aisac/` | `C:\ProgramData\AISAC\` |
| Datos | `/var/lib/aisac/` | `C:\ProgramData\AISAC\data\` |
| Logs | `/var/log/aisac/` | `C:\ProgramData\AISAC\logs\` |
| Servicios | systemd | Windows Services |
| Nombre servicio agente | `aisac-agent` | `AISACAgent` |
| Nombre servicio CS | `aisac-server` | `AISACServer` |

### Fuentes de logs en Windows

- **Windows Security Event Log** - Canal nativo de seguridad
- **Sysmon** - Si el servicio esta activo (`Microsoft-Windows-Sysmon/Operational`)
- **Suricata** - `C:\Program Files\Suricata\log\eve.json`
- **Wazuh** - `C:\Program Files (x86)\ossec-agent\logs\alerts\alerts.json`

---

## 5. Instalacion no interactiva

Para despliegues automatizados, usar variables de entorno:

### Linux

```bash
AISAC_API_KEY="aisac_tu_api_key" \
AISAC_ASSET_ID="tu-asset-uuid" \
AISAC_SOAR=true \
AISAC_COLLECTOR=true \
AISAC_HEARTBEAT=true \
AISAC_CS_TOKEN="token-del-command-server" \
AISAC_CS_URL="https://tu-servidor:8443" \
AISAC_NONINTERACTIVE=true \
sudo -E ./scripts/install.sh
```

### Windows

```powershell
$env:AISAC_API_KEY = "aisac_tu_api_key"
$env:AISAC_ASSET_ID = "tu-asset-uuid"
$env:AISAC_SOAR = "true"
$env:AISAC_COLLECTOR = "true"
$env:AISAC_HEARTBEAT = "true"
$env:AISAC_CS_TOKEN = "token-del-command-server"
$env:AISAC_CS_URL = "https://tu-servidor:8443"
.\scripts\install.ps1 -NonInteractive
```

---

## 6. Verificacion post-instalacion

### Comprobar que los servicios estan activos

**Linux:**

```bash
# Estado del agente
sudo systemctl status aisac-agent

# Estado del Command Server (si SOAR)
sudo systemctl status aisac-server

# Logs en tiempo real
sudo journalctl -u aisac-agent -f
```

**Windows:**

```powershell
# Estado del agente
Get-Service AISACAgent

# Estado del Command Server (si SOAR)
Get-Service AISACServer

# Logs
Get-Content "C:\ProgramData\AISAC\logs\agent.log" -Wait
```

### Verificar conectividad

```bash
# Comprobar que el heartbeat llega a la plataforma
# (buscar "heartbeat sent" en los logs)
sudo journalctl -u aisac-agent --since "1 min ago" | grep heartbeat

# Si SOAR: verificar conexion WebSocket al Command Server
sudo journalctl -u aisac-agent --since "1 min ago" | grep -i "connected\|websocket"

# Si SOAR: listar agentes conectados al Command Server
curl -sk https://localhost:8443/api/v1/agents \
  -H "X-API-Token: $(cat /etc/aisac/server-api-token)"
```

### Verificar certificados (solo SOAR)

```bash
openssl verify -CAfile /etc/aisac/certs/ca.crt /etc/aisac/certs/agent.crt
openssl verify -CAfile /etc/aisac/certs/ca.crt /etc/aisac/certs/server.crt
```

### Comprobar registro en la plataforma

Ir al Dashboard de AISAC > Assets > [Tu asset]. Debe aparecer:
- Estado: **Online**
- Agent ID: `agent-{hostname}-{random}`
- Ultima actividad: reciente

---

## 7. Modos de operacion

El agente soporta diferentes combinaciones segun las necesidades:

### Solo Heartbeat (minimo)

Reporta estado del asset. Sin coleccion de logs ni respuesta a incidentes.

```
Requisitos: API Key + Asset ID
Servicios:  aisac-agent
```

### Colector + Heartbeat (SIEM)

Reenvia logs de seguridad a la plataforma para analisis.

```
Requisitos: API Key + Asset ID + fuentes de logs instaladas
Servicios:  aisac-agent
```

### SOAR completo (respuesta a incidentes)

Recibe y ejecuta comandos de respuesta automatizada (bloquear IP, aislar host, etc).

```
Requisitos: API Key + Asset ID + certificados mTLS + Command Server
Servicios:  aisac-agent + aisac-server
```

### Combinado (recomendado)

Todas las capacidades habilitadas.

```
Requisitos: API Key + Asset ID + certificados mTLS + Command Server + fuentes de logs
Servicios:  aisac-agent + aisac-server
```

---

## 8. Dependencias opcionales

### Fuentes de logs

El agente recopila logs de herramientas de seguridad que deben instalarse independientemente:

| Herramienta | Funcion | Instalacion |
|-------------|---------|-------------|
| [Suricata](https://suricata.io/) | IDS/IPS de red | `apt install suricata` / `yum install suricata` |
| [Wazuh Agent](https://documentation.wazuh.com/) | HIDS (deteccion en host) | [Guia oficial](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html) |
| Syslog | Logs del sistema | Incluido en el SO |
| [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) (Windows) | Monitoreo avanzado | Descarga de Sysinternals |

> **Nota**: El agente funciona sin estas herramientas. Solo se habilita la coleccion de las fuentes que esten disponibles.

### Go (para compilar desde fuente)

Si el instalador se ejecuta desde el repositorio clonado y Go esta disponible, compila los binarios directamente. Si no, descarga binarios precompilados de GitHub Releases.

```bash
# Instalar Go 1.21+ (si se necesita compilar)
# Ubuntu/Debian
sudo apt install golang-go

# O desde la web oficial
# https://go.dev/dl/
```

### OpenSSL (para certificados SOAR)

Necesario solo si se habilita SOAR con generacion automatica de certificados.

```bash
# Linux (generalmente ya instalado)
openssl version

# Windows: descargar desde
# https://slproweb.com/products/Win32OpenSSL.html
```

---

## 9. Desinstalacion

### Linux

```bash
sudo ./scripts/install.sh --uninstall
```

Opciones:
- Detiene y elimina los servicios systemd
- Elimina binarios de `/opt/aisac/` y `/usr/local/bin/`
- **Pregunta** si eliminar configuracion, datos y certificados

### Windows

```powershell
.\scripts\install.ps1 -Uninstall
```

Mismo comportamiento: detiene servicios, elimina binarios, y opcionalmente elimina datos.

---

## 10. Referencia de variables de entorno

Variables para la instalacion no interactiva y configuracion del agente:

| Variable | Requerida | Descripcion |
|----------|-----------|-------------|
| `AISAC_API_KEY` | Si | API Key de la plataforma (`aisac_xxxx...`) |
| `AISAC_ASSET_ID` | Si | UUID del asset en la plataforma |
| `AISAC_AGENT_ID` | No | Forzar un Agent ID especifico (sobreescribe el persistido) |
| `AISAC_SOAR` | No | Habilitar SOAR (`true`/`false`, default: `false`) |
| `AISAC_COLLECTOR` | No | Habilitar colector (`true`/`false`, default: `true`) |
| `AISAC_HEARTBEAT` | No | Habilitar heartbeat (`true`/`false`, default: `true`) |
| `AISAC_CS_TOKEN` | No | Token API del Command Server (para SOAR) |
| `AISAC_CS_URL` | No | URL publica del Command Server (para SOAR) |
| `AISAC_REGISTER_URL` | No | Sobreescribir URL de registro (para staging) |
| `AISAC_NONINTERACTIVE` | No | Modo no interactivo (`true`/`false`) |
| `AISAC_SERVER_URL` | No | URL WebSocket del Command Server |
| `AISAC_LOG_LEVEL` | No | Nivel de log (`debug`, `info`, `warn`, `error`) |

---

## 11. Resolucion de problemas

### El servicio no arranca

```bash
# Ver logs detallados
sudo journalctl -u aisac-agent -n 50 --no-pager

# Verificar configuracion YAML
cat /etc/aisac/agent.yaml

# Ejecutar manualmente para ver errores
sudo /opt/aisac/aisac-agent -c /etc/aisac/agent.yaml
```

### Heartbeat devuelve 401

- Verificar que el `api_key` en `agent.yaml` coincide con el de la plataforma
- Verificar que el `asset_id` existe en la plataforma
- Comprobar que no hay caracteres extra (comillas, espacios) en el YAML

### Conexion WebSocket rechazada (SOAR)

```bash
# Verificar que el Command Server esta corriendo
sudo systemctl status aisac-server

# Verificar que el puerto 8443 esta escuchando
ss -tlnp | grep 8443

# Probar conectividad
curl -sk https://localhost:8443/api/v1/agents
```

### Error de certificados

```bash
# Verificar certificados
openssl verify -CAfile /etc/aisac/certs/ca.crt /etc/aisac/certs/agent.crt

# Ver detalles del certificado
openssl x509 -in /etc/aisac/certs/agent.crt -text -noout

# Regenerar certificados (requiere reinstalacion)
sudo ./scripts/install.sh
```

### El agente no aparece en la plataforma

1. Comprobar que el registro fue exitoso en los logs de instalacion
2. Verificar que el `asset_id` corresponde a un asset existente
3. Si se reinstalo, el agente puede tener un nuevo ID — verificar en los logs:
   ```bash
   grep "Agent ID" /var/log/aisac/agent.log
   ```

### N8n recibe 404 "Agent not found"

El `agent_id` que usa n8n no coincide con el del agente conectado:

```bash
# Ver el agent_id actual conectado al Command Server
curl -sk https://localhost:8443/api/v1/agents \
  -H "X-API-Token: $(cat /etc/aisac/server-api-token)"

# Comparar con el agent_id que n8n esta usando
# Si no coinciden, re-registrar el agente o actualizar n8n
```

### Token del Command Server invalido

Si n8n recibe 401 al enviar comandos al CS:

```bash
# Ver el token que el CS espera
cat /etc/aisac/server-api-token

# Comparar con el token que n8n esta enviando
# Deben ser identicos, sin comillas ni espacios extra
```

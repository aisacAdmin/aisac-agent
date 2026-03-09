# Guia de Instalacion - AISAC Agent (Endpoints)

Guia para instalar el agente AISAC en servidores y estaciones de trabajo Linux y Windows.

## Indice

1. [Que se instala](#1-que-se-instala)
2. [Requisitos previos](#2-requisitos-previos)
3. [Obtener credenciales](#3-obtener-credenciales)
4. [Instalacion en Linux](#4-instalacion-en-linux)
5. [Instalacion en Windows](#5-instalacion-en-windows)
6. [Modo SOAR](#6-modo-soar)
7. [Verificacion post-instalacion](#7-verificacion-post-instalacion)
8. [Que se configura automaticamente](#8-que-se-configura-automaticamente)
9. [Desinstalacion](#9-desinstalacion)
10. [Resolucion de problemas](#10-resolucion-de-problemas)

---

## 1. Que se instala

El instalador configura automaticamente dos componentes en cada endpoint:

| Componente | Descripcion |
|------------|-------------|
| **Wazuh Agent** | Agente HIDS que reporta al Wazuh Manager centralizado |
| **AISAC Agent** | Heartbeat de estado + reenvio de logs locales a la plataforma AISAC |

Opcionalmente, con el flag `--soar` / `-Soar`, tambien instala:

| Componente | Descripcion |
|------------|-------------|
| **Command Server** | Servidor WebSocket con mTLS para recibir acciones SOAR |

### Arquitectura

```
  ┌──────────────────────────────────┐
  │         Endpoint (este equipo)   │
  │                                  │
  │  Wazuh Agent ──────────────────────> Wazuh Manager (1514/1515)
  │                                  │        │
  │  AISAC Agent ──────────────────────> Plataforma AISAC (HTTPS 443)
  │    - Heartbeat (estado)          │        │
  │    - Collector (logs locales)    │        v
  │    - SOAR (acciones, opcional)   │  AISAC Collector (en Manager)
  └──────────────────────────────────┘    - alerts.json ──> Plataforma AISAC
```

> **Nota**: Las alertas de seguridad de Wazuh (SSH brute force, sudo, etc.) las genera el **Manager** en `alerts.json`. El AISAC Collector que corre en el Manager es el que las envia a la plataforma AISAC. El AISAC Agent del endpoint envia heartbeat y logs locales (syslog, Suricata).

---

## 2. Requisitos previos

### Sistemas operativos soportados

| SO | Versiones |
|----|-----------|
| **Ubuntu** | 20.04, 22.04, 24.04 LTS |
| **Debian** | 11, 12 |
| **CentOS / RHEL** | 7, 8, 9 |
| **Rocky Linux / AlmaLinux** | 8, 9 |
| **Windows Server** | 2016, 2019, 2022 |
| **Windows** | 10, 11 |

### Requisitos del sistema

| Requisito | Linux | Windows |
|-----------|-------|---------|
| Acceso | root / sudo | Administrador |
| Init system | systemd | Windows Services |
| Shell | bash | PowerShell 5.0+ |
| Descarga | curl | PowerShell (Invoke-WebRequest) |

### Arquitecturas soportadas

- **Linux**: amd64 (x86_64), arm64 (aarch64)
- **Windows**: amd64

### Conectividad de red

| Destino | Puerto | Uso |
|---------|--------|-----|
| Wazuh Manager | 1514/TCP+UDP | Comunicacion del agente Wazuh |
| Wazuh Manager | 1515/TCP | Registro del agente Wazuh |
| `api.aisac.cisec.es` | 443/TCP | Plataforma AISAC (heartbeat + logs) |

> **Importante**: Los puertos 1514 (TCP y UDP) y 1515 (TCP) deben estar abiertos en el firewall/security group del **Manager**, no del endpoint.

---

## 3. Obtener credenciales

Necesitas tres datos antes de instalar:

### 3.1 IP del Wazuh Manager

La IP (publica o privada) del servidor donde esta instalado el Wazuh Manager.

- Si el endpoint esta en la **misma red/VPC** que el Manager: usar la IP privada
- Si el endpoint esta en **otra red**: usar la IP publica del Manager

### 3.2 API Key del asset

1. Accede al Dashboard AISAC
2. Ve a **Assets** y crea el asset que representa a este endpoint
3. Copia la **API Key** (formato: `aisac_xxxx...`)

### 3.3 Auth Token (JWT)

Token JWT proporcionado por el administrador de la plataforma. Necesario para autenticarse contra el gateway de la API.

> **Nota**: Los tres parametros son obligatorios. Sin ellos la instalacion no se iniciara.

---

## 4. Instalacion en Linux

### Paso 1: Descargar los scripts

```bash
curl -sSL https://raw.githubusercontent.com/CISECSL/aisac-agent/main/scripts/install.sh -o install.sh
curl -sSL https://raw.githubusercontent.com/CISECSL/aisac-agent/main/scripts/install-wazuh-agent.sh -o install-wazuh-agent.sh
curl -sSL https://raw.githubusercontent.com/CISECSL/aisac-agent/main/scripts/install-aisac-agent.sh -o install-aisac-agent.sh
chmod +x install.sh install-wazuh-agent.sh install-aisac-agent.sh
```

> **Nota**: Los tres scripts deben estar en la misma carpeta. `install.sh` es el orquestador que llama a los otros dos.

### Paso 2: Ejecutar el instalador

```bash
sudo ./install.sh -k <API_KEY> -t <AUTH_TOKEN> -m <MANAGER_IP>
```

**Ejemplo:**

```bash
sudo ./install.sh \
  -k aisac_abc123def456 \
  -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... \
  -m 54.78.120.30
```

### Parametros

| Parametro | Obligatorio | Descripcion |
|-----------|-------------|-------------|
| `-k <API_KEY>` | Si | API Key del asset en la plataforma AISAC |
| `-t <AUTH_TOKEN>` | Si | Token JWT para autenticacion con el gateway |
| `-m <MANAGER_IP>` | Si | IP del Wazuh Manager |
| `-u <URL>` | No | URL del endpoint install-config (por defecto: `https://api.aisac.cisec.es/functions/v1/install-config`) |
| `--soar` | No | Habilitar modo SOAR (Command Server + certificados mTLS) |
| `--uninstall` | No | Desinstalar AISAC Agent, Command Server y Wazuh Agent |
| `-h, --help` | No | Mostrar ayuda |

### Que hace el instalador

```
  Step 1/2: Instalar Wazuh Agent
    - Llama al endpoint install-config con la API Key para obtener la configuracion
    - Descarga e instala el paquete Wazuh Agent
    - Configura la conexion al Manager (IP, puerto, grupo, nombre)
    - Inicia el servicio wazuh-agent

  Step 2/2: Instalar AISAC Agent
    - Instala el binario aisac-agent
    - Genera la configuracion (heartbeat + collector)
    - Auto-detecta fuentes de logs locales (Suricata, Wazuh alerts, Syslog)
    - Instala e inicia el servicio systemd
    - Si --soar: genera certificados mTLS, instala Command Server
```

### Estructura de directorios

```
/opt/aisac/
  aisac-agent                    # Binario del agente
  aisac-server                   # Binario del Command Server (solo con --soar)

/etc/aisac/
  agent.yaml                     # Configuracion
  certs/                         # Certificados mTLS (solo con --soar)
    ca.crt
    agent.crt
    agent.key
    server.crt
    server.key

/var/lib/aisac/
  agent-id                       # ID persistente del agente
  sincedb.json                   # Posicion de lectura de logs
  safety_state.json              # Estado interno

/var/log/aisac/
  agent.log                      # Logs del agente
```

---

## 5. Instalacion en Windows

### Paso 1: Descargar los scripts

Descargar los tres scripts de instalacion en una carpeta:

```powershell
# Crear carpeta temporal
New-Item -ItemType Directory -Path "$env:TEMP\aisac-install" -Force
cd "$env:TEMP\aisac-install"

# Descargar scripts
$baseUrl = "https://raw.githubusercontent.com/CISECSL/aisac-agent/main/scripts"
@("install.ps1", "install-wazuh-agent.ps1", "install-aisac-agent.ps1") | ForEach-Object {
    Invoke-WebRequest -Uri "$baseUrl/$_" -OutFile $_ -UseBasicParsing
}
```

### Paso 2: Ejecutar el instalador

Abrir PowerShell **como Administrador**:

```powershell
.\install.ps1 -ApiKey <API_KEY> -AuthToken <AUTH_TOKEN> -ManagerIp <MANAGER_IP>
```

**Ejemplo:**

```powershell
.\install.ps1 `
  -ApiKey aisac_abc123def456 `
  -AuthToken eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... `
  -ManagerIp 54.78.120.30
```

### Parametros

| Parametro | Obligatorio | Equivalente Linux | Descripcion |
|-----------|-------------|-------------------|-------------|
| `-ApiKey` | Si | `-k` | API Key del asset en la plataforma AISAC |
| `-AuthToken` | Si | `-t` | Token JWT para autenticacion con el gateway |
| `-ManagerIp` | Si | `-m` | IP del Wazuh Manager |
| `-ConfigUrl` | No | `-u` | URL del endpoint install-config (por defecto: produccion) |
| `-Soar` | No | `--soar` | Habilitar modo SOAR (Command Server + certificados mTLS) |
| `-Uninstall` | No | `--uninstall` | Desinstalar AISAC Agent, Command Server y Wazuh Agent |
| `-Help` | No | `-h` | Mostrar ayuda |

> Los parametros de Windows son identicos en funcionalidad a los de Linux, solo cambia la nomenclatura (PowerShell named params vs POSIX flags).

### Que hace el instalador

```
  Step 1/2: Instalar Wazuh Agent
    - Llama al endpoint install-config con la API Key para obtener la configuracion
    - Descarga e instala el MSI de Wazuh Agent
    - Configura la conexion al Manager (IP, puerto, grupo, nombre)
    - Extrae el Wazuh Agent ID de client.keys e inyecta metadatos en el registro
    - Inicia el servicio WazuhSvc

  Step 2/2: Instalar AISAC Agent
    - Instala el binario aisac-agent.exe via NSSM (wrapper de servicios)
    - Genera la configuracion (heartbeat + collector)
    - Auto-detecta fuentes de logs locales (Suricata, Wazuh alerts)
    - Instala e inicia el servicio AISACAgent
    - Registra el agente en la plataforma con metadatos Wazuh (agent_name, agent_id)
    - Si -Soar: genera certificados mTLS (requiere OpenSSL en PATH), instala Command Server
```

### Estructura de directorios

```
C:\Program Files\AISAC\
  aisac-agent.exe                # Binario del agente
  aisac-server.exe               # Binario del Command Server (solo con -Soar)
  nssm.exe                       # Wrapper de servicios

C:\ProgramData\AISAC\
  agent.yaml                     # Configuracion
  server-api-token               # Token del Command Server (solo con -Soar)
  certs\                         # Certificados mTLS (solo con -Soar)
  data\
    agent-id                     # ID persistente del agente
    sincedb.json                 # Posicion de lectura de logs
    safety_state.json            # Estado interno
  logs\
    agent.log                    # Logs del agente
    service-stdout.log           # Salida del servicio
    service-stderr.log           # Errores del servicio
```

---

## 6. Modo SOAR

El modo SOAR habilita la ejecucion de acciones de respuesta a incidentes desde la plataforma AISAC.

### Activar modo SOAR

**Linux:**

```bash
sudo ./install.sh -k <API_KEY> -t <AUTH_TOKEN> -m <MANAGER_IP> --soar
```

**Windows:**

```powershell
.\install.ps1 -ApiKey <API_KEY> -AuthToken <AUTH_TOKEN> -ManagerIp <MANAGER_IP> -Soar
```

> **Requisito Windows**: El modo SOAR en Windows requiere **OpenSSL** instalado y disponible en PATH para generar los certificados mTLS.

### Que se instala adicionalmente

- **Command Server**: Servidor WebSocket que recibe comandos de la plataforma
- **Certificados mTLS**: CA autofirmada + certificados de agente y servidor para comunicacion segura
- **Registro del agente**: El agente se registra automaticamente en la plataforma con la URL y token del Command Server

### Servicios adicionales

**Linux:**

```bash
sudo systemctl status aisac-server    # Command Server
```

**Windows:**

```powershell
Get-Service AISACServer               # Command Server
```

### Acciones SOAR disponibles

| Accion | Descripcion |
|--------|-------------|
| `block_ip` / `unblock_ip` | Bloquear/desbloquear IP en el firewall |
| `isolate_host` / `unisolate_host` | Aislar/restaurar conectividad de red |
| `disable_user` / `enable_user` | Deshabilitar/habilitar cuenta de usuario |
| `kill_process` | Terminar un proceso |
| `dns_lookup` | Resolucion DNS |
| `check_hash` | Consultar reputacion de hash |
| `check_ip_reputation` | Consultar reputacion de IP |
| `search_ioc` | Buscar indicadores de compromiso |
| `collect_forensics` | Recopilar evidencia forense |
| `threat_hunt` | Buscar actividad sospechosa |

---

## 7. Verificacion post-instalacion

### 7.1 Comprobar servicios

**Linux:**

```bash
# Wazuh Agent
sudo systemctl status wazuh-agent

# AISAC Agent
sudo systemctl status aisac-agent

# Command Server (solo con --soar)
sudo systemctl status aisac-server
```

**Windows:**

```powershell
# Wazuh Agent
Get-Service WazuhSvc

# AISAC Agent
Get-Service AISACAgent

# Command Server (solo con -Soar)
Get-Service AISACServer
```

Todos deben estar en estado **Running**.

### 7.2 Verificar conexion con el Manager

**Linux:**

```bash
# Ver estado del agente Wazuh
sudo /var/ossec/bin/agent_control -i 000

# Ver logs de conexion
sudo tail -20 /var/ossec/logs/ossec.log
```

**Windows:**

```powershell
# Ver logs de Wazuh
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20
```

### 7.3 Verificar heartbeat AISAC

**Linux:**

```bash
tail -f /var/log/aisac/agent.log
```

**Windows:**

```powershell
Get-Content "C:\ProgramData\AISAC\logs\agent.log" -Wait
```

Buscar mensajes de heartbeat exitosos. En la plataforma AISAC, el asset debe aparecer como **Online**.

---

## 8. Que se configura automaticamente

El instalador genera la configuracion en base a la respuesta del endpoint `install-config`:

| Componente | Configuracion |
|------------|---------------|
| **Wazuh Agent** | IP y puerto del Manager, nombre del agente, grupo del tenant |
| **Heartbeat** | URL, API Key, Asset ID, Auth Token, intervalo de 120s |
| **Collector** | Se habilita automaticamente si detecta fuentes de logs locales |
| **SOAR** | Command Server + mTLS + registro (solo con `--soar` / `-Soar`) |

### Fuentes de logs auto-detectadas

El instalador busca automaticamente las siguientes fuentes y habilita el collector si encuentra alguna:

| Fuente | Parser | Ruta (Linux) | Ruta (Windows) |
|--------|--------|-------------|----------------|
| Suricata EVE | `suricata_eve` | `/var/log/suricata/eve.json` | `C:\Program Files\Suricata\log\eve.json` |
| Wazuh Alerts | `wazuh_alerts` | `/var/ossec/logs/alerts/alerts.json` | `C:\Program Files (x86)\ossec-agent\logs\alerts\alerts.json` |
| Syslog | `syslog` | `/var/log/syslog` o `/var/log/messages` | — (no aplica en Windows) |

> Si no se detecta ninguna fuente, el collector queda deshabilitado. Se puede habilitar manualmente editando `agent.yaml`.

### Metadatos Wazuh

Durante la instalacion, el script de Wazuh (`install-wazuh-agent.sh` / `install-wazuh-agent.ps1`) extrae el **Wazuh Agent ID** y el **nombre del agente** y los inyecta en el fichero de registro temporal. El script de AISAC (`install-aisac-agent.sh` / `install-aisac-agent.ps1`) los lee y envia como `integration_config` al registrar el agente en la plataforma. Esto permite que la plataforma asocie las alertas de Wazuh (que llegan via el Manager) con el asset correcto.


---

## 9. Desinstalacion

El instalador incluye un flag de desinstalacion que elimina AISAC Agent, Command Server y Wazuh Agent.

### Usando el instalador (recomendado)

**Linux:**

```bash
sudo ./install.sh --uninstall
```

**Windows:**

```powershell
.\install.ps1 -Uninstall
```

El proceso pedira confirmacion antes de proceder y preguntara si desea eliminar tambien la configuracion, datos y certificados.

### Desinstalacion manual

**Linux:**

```bash
# Parar y deshabilitar servicios
sudo systemctl stop aisac-agent aisac-server
sudo systemctl disable aisac-agent aisac-server
sudo systemctl stop wazuh-agent
sudo systemctl disable wazuh-agent

# Eliminar servicios AISAC
sudo rm -f /etc/systemd/system/aisac-agent.service
sudo rm -f /etc/systemd/system/aisac-server.service
sudo systemctl daemon-reload

# Eliminar archivos AISAC
sudo rm -rf /opt/aisac /etc/aisac /var/lib/aisac /var/log/aisac
sudo rm -f /usr/local/bin/aisac-agent /usr/local/bin/aisac-server

# Eliminar Wazuh Agent
sudo apt remove --purge wazuh-agent -y    # Debian/Ubuntu
# o
sudo yum remove wazuh-agent -y            # CentOS/RHEL
sudo rm -rf /var/ossec
```

> **Nota**: Si el agente estaba registrado en el Manager, tambien hay que eliminarlo alli:
> ```bash
> # En el Manager
> sudo /var/ossec/bin/manage_agents -r <AGENT_ID>
> sudo systemctl restart wazuh-manager
> ```

**Windows:**

```powershell
# Parar servicios
Stop-Service AISACAgent, AISACServer, WazuhSvc -Force -ErrorAction SilentlyContinue

# Eliminar servicios AISAC
sc.exe delete AISACAgent
sc.exe delete AISACServer

# Eliminar archivos AISAC
Remove-Item "C:\Program Files\AISAC" -Recurse -Force
Remove-Item "C:\ProgramData\AISAC" -Recurse -Force

# Desinstalar Wazuh Agent
$wazuh = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "Wazuh Agent*" }
if ($wazuh) { $wazuh.Uninstall() }
```

---

## 10. Resolucion de problemas

### El instalador falla con "API Key is required"

```
[ERROR] API Key is required (-k)
```

**Causa**: No se han pasado todos los parametros obligatorios.

**Solucion**: Asegurar que se pasan los tres parametros requeridos:

```bash
sudo ./install.sh -k <API_KEY> -t <AUTH_TOKEN> -m <MANAGER_IP>
```

### El instalador falla con HTTP 401

```
[ERROR] install-config returned HTTP 401
```

**Causa**: La API Key o el Auth Token no son validos.

**Solucion**:
- Verificar la API Key en la plataforma (Assets > [Tu asset] > API Key)
- Verificar que el Auth Token (JWT) es correcto y no ha expirado
- Asegurar que se pasan ambos parametros: `-k` y `-t`

### Wazuh Agent no conecta al Manager

```bash
# Linux - ver logs de conexion
sudo grep -i "agentd\|error\|unable\|connect" /var/ossec/logs/ossec.log | tail -20

# Verificar que tiene clave de registro
sudo cat /var/ossec/etc/client.keys

# Verificar conectividad al Manager
nc -zv <MANAGER_IP> 1514 -w 3
```

**Causas posibles**:
- La IP del Manager (`-m`) es incorrecta
- Los puertos 1514 (TCP **y** UDP) y 1515 (TCP) no estan abiertos en el firewall del Manager
- El Manager no esta activo
- `client.keys` esta vacio (registro fallido)

**Solucion**:
1. Verificar que la IP del Manager es accesible: `nc -zv <MANAGER_IP> 1514 -w 3`
2. Asegurar que los puertos 1514 (TCP+UDP) y 1515 (TCP) estan abiertos en el security group del Manager
3. Si `client.keys` esta vacio, verificar que el puerto 1515 esta accesible y reinstalar el Wazuh Agent

### Wazuh Agent "Never connected" en el Manager

El agente se registro (tiene ID asignado) pero nunca establecio comunicacion.

```bash
# En el Manager
sudo /var/ossec/bin/agent_control -l
# ID: 001, Name: agent-name, IP: any, Never connected
```

**Causa mas comun**: Puerto **1514 UDP** no abierto en el firewall del Manager. El registro usa TCP 1515, pero la comunicacion de datos requiere TCP y UDP 1514.

**Solucion**:
1. Abrir TCP y UDP 1514 en el security group / firewall del Manager
2. Si persiste, eliminar el agente del Manager y reinstalar en el endpoint:

```bash
# En el Manager
sudo /var/ossec/bin/manage_agents -r <AGENT_ID>
sudo systemctl restart wazuh-manager

# En el endpoint
sudo systemctl restart wazuh-agent
```

### Heartbeat devuelve 401

```bash
grep -i "401\|unauthorized" /var/log/aisac/agent.log
```

**Causas posibles**:
- API Key incorrecta en la configuracion
- Auth Token ausente o invalido
- Version antigua del binario que no soporta auth_token

**Solucion**: Verificar `api_key` y `auth_token` en el fichero de configuracion:

```bash
# Linux
cat /etc/aisac/agent.yaml | grep -A2 "api_key\|auth_token"
```

```powershell
# Windows
Select-String -Path "C:\ProgramData\AISAC\agent.yaml" -Pattern "api_key|auth_token"
```

### El servicio AISAC no arranca

**Linux:**

```bash
# Ver logs detallados
sudo journalctl -u aisac-agent -n 50 --no-pager

# Ejecutar manualmente
sudo /opt/aisac/aisac-agent -c /etc/aisac/agent.yaml
```

**Windows:**

```powershell
# Ver logs
Get-Content "C:\ProgramData\AISAC\logs\service-stderr.log" -Tail 50

# Ejecutar manualmente
& "C:\Program Files\AISAC\aisac-agent.exe" -c "C:\ProgramData\AISAC\agent.yaml"
```

### El asset no aparece como Online en la plataforma

1. Verificar que el servicio `aisac-agent` esta activo
2. Buscar errores de heartbeat en los logs
3. Verificar conectividad HTTPS: `curl -v https://api.aisac.cisec.es`
4. Comprobar que el `asset_id` en la configuracion coincide con el de la plataforma

### Windows: El servicio no arranca tras reiniciar

Los servicios AISAC en Windows usan NSSM como wrapper. Si el servicio no arranca:

```powershell
# Ver estado detallado
& "C:\Program Files\AISAC\nssm.exe" status AISACAgent

# Ver logs de error del wrapper
Get-Content "C:\ProgramData\AISAC\logs\service-stderr.log" -Tail 30

# Reinstalar el servicio manualmente si se corrompio
& "C:\Program Files\AISAC\nssm.exe" remove AISACAgent confirm
& "C:\Program Files\AISAC\nssm.exe" install AISACAgent "C:\Program Files\AISAC\aisac-agent.exe" "-c `"C:\ProgramData\AISAC\agent.yaml`""
Start-Service AISACAgent
```

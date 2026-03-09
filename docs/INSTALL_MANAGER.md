# Guia de Instalacion - Wazuh Manager + AISAC Collector

Guia para instalar el servidor centralizado Wazuh Manager con el colector AISAC integrado.

## Indice

1. [Que se instala](#1-que-se-instala)
2. [Requisitos previos](#2-requisitos-previos)
3. [Obtener credenciales](#3-obtener-credenciales)
4. [Instalacion](#4-instalacion)
5. [Verificacion post-instalacion](#5-verificacion-post-instalacion)
6. [Configuracion de red](#6-configuracion-de-red)
7. [Administracion del Manager](#7-administracion-del-manager)
8. [Resolucion de problemas](#8-resolucion-de-problemas)

---

## 1. Que se instala

El script `install-manager.sh` instala y configura automaticamente:

| Componente | Descripcion |
|------------|-------------|
| **Wazuh Indexer** | Motor de indexacion para alertas (basado en OpenSearch) |
| **Wazuh Server** | Manager central que recibe datos de los agentes Wazuh |
| **Wazuh Dashboard** | Interfaz web para visualizacion de alertas |
| **AISAC Agent (Collector)** | Reenvio de alertas Wazuh a la plataforma AISAC |

### Arquitectura resultante

```
                    Agentes Wazuh
                   (puertos 1514/1515)
                         |
                         v
              ┌─────────────────────┐
              │    Wazuh Manager    │
              │  (este servidor)    │
              │                     │
              │  alerts.json ──────>│── AISAC Collector ──> Plataforma AISAC
              │                     │     (heartbeat + logs)
              │  Dashboard :443     │
              └─────────────────────┘
```

---

## 2. Requisitos previos

### Sistema operativo

- **Ubuntu** 20.04 / 22.04 / 24.04 LTS
- **Debian** 11 / 12
- **CentOS** 7 / 8 / Rocky Linux / AlmaLinux

### Recursos minimos

| Recurso | Minimo | Recomendado |
|---------|--------|-------------|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 4 GB | 8 GB |
| Disco | 50 GB | 100 GB+ |

### Requisitos del sistema

- Acceso **root** o **sudo**
- **curl** instalado
- **systemd** como init system
- Conectividad a internet (para descarga de paquetes)

### Conectividad de red

| Puerto | Protocolo | Direccion | Uso |
|--------|-----------|-----------|-----|
| 1514 | TCP/UDP | Entrada | Comunicacion agentes Wazuh |
| 1515 | TCP | Entrada | Registro de agentes Wazuh |
| 443 | TCP | Entrada | Dashboard Wazuh (HTTPS) |
| 443 | TCP | Salida | Plataforma AISAC (heartbeat + logs) |

---

## 3. Obtener credenciales

Antes de instalar, necesitas obtener los siguientes datos de la plataforma AISAC:

### 3.1 API Key del asset del Manager

1. Accede al Dashboard AISAC
2. Ve a **Assets** y selecciona (o crea) el asset que representa al Manager
3. Copia la **API Key** (formato: `aisac_xxxx...`)

### 3.2 Auth Token (JWT)

El Auth Token es proporcionado por el administrador de la plataforma. Es un token JWT necesario para autenticarse contra el gateway de la API.

> **Nota**: Ambas credenciales son obligatorias. Sin ellas la instalacion fallara al intentar conectar con la plataforma.

---

## 4. Instalacion

### Paso 1: Descargar el script

```bash
curl -sSL https://raw.githubusercontent.com/CISECSL/aisac-agent/main/scripts/install-manager.sh -o install-manager.sh
```

### Paso 2: Ejecutar el instalador

```bash
sudo bash install-manager.sh -k <API_KEY> -t <AUTH_TOKEN>
```

**Ejemplo:**

```bash
sudo bash install-manager.sh \
  -k aisac_abc123def456 \
  -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Parametros

| Parametro | Obligatorio | Descripcion |
|-----------|-------------|-------------|
| `-k <API_KEY>` | Si | API Key del asset en la plataforma AISAC |
| `-t <AUTH_TOKEN>` | Si | Token JWT para autenticacion con el gateway |
| `-u <URL>` | No | URL del endpoint install-config (por defecto: produccion) |
| `-i` | No | Ignorar requisitos minimos de hardware (para VMs pequenas) |
| `--no-indexer` | No | Instalar solo Wazuh Manager sin Indexer ni Dashboard (~500 MB RAM) |
| `-h` | No | Mostrar ayuda |

### Instalacion ligera (sin Indexer ni Dashboard)

Para servidores con recursos limitados (1 vCPU, 1-2 GB RAM):

```bash
sudo bash install-manager.sh \
  -k aisac_abc123def456 \
  -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... \
  --no-indexer -i
```

Esto instala solo el Wazuh Manager + AISAC Collector, sin el Indexer ni el Dashboard.

### Que hace el instalador

El proceso se ejecuta en 5 pasos automaticos:

```
  Step 1/5: Detectar configuracion del servidor (IP privada)
  Step 2/5: Instalar Wazuh Manager (indexer + server + dashboard)
  Step 3/5: Obtener configuracion de la plataforma AISAC
  Step 4/5: Crear grupo de tenant en el Wazuh Manager
  Step 5/5: Instalar AISAC Collector (heartbeat + reenvio de alertas)
```

> **Nota**: Si el Wazuh Manager ya esta instalado en el servidor, el paso 2 se omite automaticamente.
> Con `--no-indexer`, los pasos de Indexer y Dashboard se omiten.

### Estructura de directorios resultante

```
/var/ossec/                          # Wazuh Manager
  bin/                               # Binarios de Wazuh
  logs/alerts/alerts.json            # Alertas (leidas por AISAC Collector)

/opt/aisac/                          # AISAC Agent
  aisac-agent                        # Binario

/etc/aisac/                          # Configuracion AISAC
  agent.yaml                         # Config del collector

/var/lib/aisac/                      # Datos persistentes
  sincedb.json                       # Posicion de lectura de logs
  safety_state.json                  # Estado interno

/var/log/aisac/                      # Logs del collector
  agent.log
```

---

## 5. Verificacion post-instalacion

### 5.1 Comprobar servicios

```bash
# Wazuh Manager
sudo systemctl status wazuh-manager

# Wazuh Indexer
sudo systemctl status wazuh-indexer

# Wazuh Dashboard
sudo systemctl status wazuh-dashboard

# AISAC Collector
sudo systemctl status aisac-agent
```

Todos deben estar en estado **active (running)**.

### 5.2 Acceder al Dashboard

Abrir en el navegador:

```
https://<IP_DEL_SERVIDOR>
```

Credenciales por defecto: `admin` / `admin`

> Se recomienda cambiar la contrasena de admin despues de la primera sesion.

### 5.3 Verificar el heartbeat

```bash
# Ver logs del collector
tail -f /var/log/aisac/agent.log

# Buscar heartbeats exitosos
grep -i "heartbeat" /var/log/aisac/agent.log | tail -5
```

En la plataforma AISAC, el asset del Manager debe aparecer como **Online**.

### 5.4 Verificar reenvio de alertas

El collector comienza a enviar alertas en cuanto los agentes Wazuh empiezan a reportar:

```bash
# Verificar que el fichero de alertas existe
ls -la /var/ossec/logs/alerts/alerts.json

# Ver las ultimas alertas
tail -5 /var/ossec/logs/alerts/alerts.json

# Ver logs del collector buscando envios
grep -i "sent\|batch\|events" /var/log/aisac/agent.log | tail -10
```

---

## 6. Configuracion de red

### 6.1 Abrir puertos en el firewall

**Para que los agentes puedan conectarse al Manager**, es necesario abrir los puertos 1514 y 1515:

#### AWS Security Groups

1. Ir a EC2 > Security Groups > seleccionar el grupo del Manager
2. Agregar reglas de entrada:
   - **Puerto 1514 TCP** - Desde las IPs/subnets de los agentes
   - **Puerto 1514 UDP** - Desde las IPs/subnets de los agentes
   - **Puerto 1515 TCP** - Desde las IPs/subnets de los agentes (registro)

> **Importante**: Si solo se abre TCP sin UDP en el puerto 1514, algunos agentes pueden registrarse correctamente pero aparecer como "Never connected".

#### iptables

```bash
sudo iptables -A INPUT -p tcp --dport 1514 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 1514 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 1515 -j ACCEPT
sudo iptables-save
```

#### UFW (Ubuntu)

```bash
sudo ufw allow 1514
sudo ufw allow 1515/tcp
```

### 6.2 IP del Manager para los agentes

Los agentes necesitan la IP del Manager para conectarse. Usar:

- **IP publica** si los agentes estan fuera de la red del Manager
- **IP privada** si estan en la misma VPC/red local

---

## 7. Administracion del Manager

### Ver agentes registrados

```bash
# Lista de agentes
/var/ossec/bin/agent_control -l

# Solo agentes activos
/var/ossec/bin/agent_control -lc
```

### Ver grupos

```bash
/var/ossec/bin/agent_groups -l
```

### Eliminar un agente registrado

```bash
# Listar agentes
sudo /var/ossec/bin/manage_agents -l

# Eliminar agente por ID
sudo /var/ossec/bin/manage_agents -r <AGENT_ID>

# Reiniciar para aplicar
sudo systemctl restart wazuh-manager
```

### Reiniciar servicios

```bash
# Wazuh Manager
sudo systemctl restart wazuh-manager

# AISAC Collector
sudo systemctl restart aisac-agent
```

### Ver configuracion del collector

```bash
cat /etc/aisac/agent.yaml
```

### Mantenimiento de disco

El Wazuh Manager puede acumular datos que llenen el disco. Directorios a vigilar:

| Directorio | Descripcion | Accion |
|------------|-------------|--------|
| `/var/ossec/tmp/` | Archivos temporales | Se puede limpiar con el Manager parado |
| `/var/ossec/queue/vd/` | Base de datos de vulnerabilidades | Deshabilitar vulnerability detection si no se usa |
| `/var/ossec/queue/indexer/` | Cola del indexer | Se puede limpiar si no se usa el Indexer |

Para limpiar:

```bash
sudo systemctl stop wazuh-manager
sudo rm -rf /var/ossec/tmp/* /var/ossec/queue/vd/* /var/ossec/queue/indexer/*
sudo systemctl start wazuh-manager
```

> **Importante**: Siempre parar el servicio antes de limpiar, o los archivos abiertos no liberaran espacio.

---

## 8. Resolucion de problemas

### El instalador falla con HTTP 401

```
[ERROR] install-config returned HTTP 401
```

**Causa**: El Auth Token (`-t`) no es valido o no se ha proporcionado.

**Solucion**: Verificar que se pasa el token JWT correcto con `-t`.

### AISAC Collector no arranca

```bash
# Ver logs detallados
sudo journalctl -u aisac-agent -n 50 --no-pager

# Ejecutar manualmente para ver errores
sudo /opt/aisac/aisac-agent -c /etc/aisac/agent.yaml
```

**Causa comun**: El fichero `alerts.json` no existe todavia (se crea cuando el primer agente conecta).

**Solucion**: Esperar a que conecte el primer agente Wazuh, o verificar que el Wazuh Manager esta activo.

### Heartbeat devuelve 401

```bash
grep -i "401\|unauthorized" /var/log/aisac/agent.log
```

**Causas posibles**:
- La API Key no es valida o no corresponde al asset
- El Auth Token ha expirado o es incorrecto
- El binario del agente es una version antigua que no soporta auth_token

**Solucion**: Verificar `api_key` y `auth_token` en `/etc/aisac/agent.yaml`.

### Los agentes Wazuh no conectan

```bash
# Ver logs del Manager
sudo tail -f /var/ossec/logs/ossec.log

# Verificar que los puertos estan abiertos
ss -tlnp | grep -E '1514|1515'

# Ver estado de los agentes
sudo /var/ossec/bin/agent_control -l
```

**Causas posibles**:
- Puertos 1514 (TCP/UDP) y 1515 (TCP) no abiertos en el firewall o security group
- El agente usa una IP incorrecta del Manager
- El grupo del agente no existe en el Manager

### Agente aparece como "Never connected"

```bash
sudo /var/ossec/bin/agent_control -l
# ID: 001, Name: agent-name, IP: any, Never connected
```

El agente se registra (puerto 1515) pero no comunica (puerto 1514).

**Causas posibles**:
- Puerto **1514 UDP** no abierto en el firewall del Manager (se suele olvidar, solo se abre TCP)
- Conectividad de red entre agente y Manager bloqueada

**Solucion**:
1. Abrir TCP **y** UDP 1514 en el security group / firewall del Manager
2. Si persiste, eliminar y re-registrar el agente:

```bash
# En el Manager: eliminar agente
sudo /var/ossec/bin/manage_agents -r <AGENT_ID>
sudo systemctl restart wazuh-manager

# En el asset: reinstalar/reiniciar Wazuh Agent
sudo systemctl restart wazuh-agent
```

### Disco lleno en el Manager

```bash
df -h /
```

**Causa**: Wazuh Manager acumula datos en `/var/ossec/tmp/`, `/var/ossec/queue/vd/` y `/var/ossec/queue/indexer/`.

**Solucion**: Ver la seccion [Mantenimiento de disco](#mantenimiento-de-disco) en Administracion del Manager.

### Dashboard no accesible

```bash
# Verificar servicio
sudo systemctl status wazuh-dashboard

# Verificar puerto 443
ss -tlnp | grep 443
```

**Solucion**: Asegurar que el puerto 443 esta abierto en el firewall para acceso desde el navegador.

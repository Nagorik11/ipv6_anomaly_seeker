#!/bin/bash

echo "==============================================="
echo "  IPv6 ADVANCED SECURITY & ANOMALY AUDIT v2.1"
echo "==============================================="
echo "Inicio: $(date)"
echo

# Configuración
OUTPUT_FILE="ipv6_audit_report_$(date +%Y%m%d_%H%M%S).json"
SCAN_DATA=""

# Función para logging
log() {
    echo "$1"
    SCAN_DATA="${SCAN_DATA}$1\n"
}

# Función para verificar dependencias
check_dependencies() {
    local missing=()
    
    for dep in "$@"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log "[ERROR] Dependencias faltantes: ${missing[*]}"
        return 1
    fi
    return 0
}

# Función para verificar conexión a internet
check_internet() {
    if ! ping -c 1 -W 3 8.8.8.8 &> /dev/null && ! ping6 -c 1 -W 3 2001:4860:4860::8888 &> /dev/null; then
        log "[⚠] Sin conexión a internet - omitiendo chequeos externos"
        return 1
    fi
    return 0
}

# ================================
# 1. DETECCIÓN DE IPv6
# ================================
log "==============================================="
log " 1. DETECCIÓN DE IPv6"
log "==============================================="

GLOBAL_V6=$(ip -6 addr 2>/dev/null | grep "scope global" | awk '{print $2}' | sed 's|/.*||' | head -1)

if [ -z "$GLOBAL_V6" ]; then
    log "[!] No IPv6 global detectada — no hay exposición externa."
else
    log "[✔] IPv6 global detectada: $GLOBAL_V6"
fi

# Detección mejorada de direcciones temporales
TEMP_V6=$(ip -6 addr 2>/dev/null | grep "temporary" | awk '{print $2}')
if [ -n "$TEMP_V6" ]; then
    log "[✔] IPv6 temporales activas (privacy OK)"
    log "$TEMP_V6"
else
    log "[⚠] No se detectan IPv6 temporales — privacidad menor."
fi

# ================================
# 2. SERVICIOS ESCUCHANDO
# ================================
log
log "==============================================="
log " 2. Servicios escuchando en IPv6 (TCP/UDP)"
log "==============================================="

check_dependencies "ss" || exit 1

LISTEN_V6=$(ss -tulpen 2>/dev/null | grep -E "tcp6|udp6")

if [ -z "$LISTEN_V6" ]; then
    log "[✔] Ningún servicio escucha en IPv6."
else
    log "[!] Servicios detectados:"
    log "$LISTEN_V6"
fi

# ================================
# 3. PUERTOS CRÍTICOS
# ================================
log
log "==============================================="
log " 3. EXÁMEN PROFUNDO DE PUERTOS CRÍTICOS"
log "==============================================="

if [ -n "$GLOBAL_V6" ]; then
    check_dependencies "nc" || {
        log "[⚠] Netcat no disponible - omitiendo escaneo de puertos"
    }
    
    CRITICAL_PORTS=(22 80 443 53 3306 5432 6379 27017 5000 8080 8443 9000 11211 2049 873 5984 6379 27017)
    OPEN_CRITICAL_PORTS=()
    
    for PORT in "${CRITICAL_PORTS[@]}"; do
        if timeout 1 bash -c "echo > /dev/tcp/[$GLOBAL_V6]/$PORT" 2>/dev/null; then
            log "[⚠] Puerto EXPUESTO en IPv6: $PORT"
            OPEN_CRITICAL_PORTS+=("$PORT")
        else
            log "[✔] Puerto $PORT cerrado"
        fi
    done
else
    log "[ℹ] Sin IPv6 global - omitiendo escaneo de puertos externos"
fi

# ================================
# 4. ESCANEO DE PUERTOS MEJORADO
# ================================
log
log "==============================================="
log " 4. ESCANEO DE PUERTOS ESTRATÉGICO"
log "==============================================="

if [ -n "$GLOBAL_V6" ]; then
    log "[+] Escaneando puertos comunes (1-1024)..."
    OPEN_PORTS=()
    
    # Escaneo más rápido de puertos comunes
    for p in {1..1024}; do
        (timeout 0.5 bash -c "echo > /dev/tcp/[$GLOBAL_V6]/$p" 2>/dev/null) && OPEN_PORTS+=($p)
    done &
    
    # Puertos adicionales importantes
    IMPORTANT_PORTS=(2049 2375 2376 3000 5000 5432 6379 8000 8080 8081 8443 9000 9090 9200 9300 11211 27017)
    
    for p in "${IMPORTANT_PORTS[@]}"; do
        (timeout 0.5 bash -c "echo > /dev/tcp/[$GLOBAL_V6]/$p" 2>/dev/null) && OPEN_PORTS+=($p)
    done &
    
    wait
    
    # Eliminar duplicados y ordenar
    OPEN_PORTS=($(printf "%s\n" "${OPEN_PORTS[@]}" | sort -nu))
    
    if [ ${#OPEN_PORTS[@]} -eq 0 ]; then
        log "[✔] No hay puertos abiertos en IPv6."
    else
        log "[‼] Puertos abiertos detectados:"
        printf '%d\n' "${OPEN_PORTS[@]}" | while read port; do
            log "  - Puerto $port"
        done
    fi
else
    OPEN_PORTS=()
fi
# ================================
# 5. ANÁLISIS EXTERNO AVANZADO
# ================================
log
log "==============================================="
log " 5. ANÁLISIS EXTERNO AVANZADO"
log "==============================================="

if check_internet; then
    check_dependencies "curl" || {
        log "[⚠] curl no disponible - omitiendo análisis externo"
    }

    log "[+] Obteniendo información externa de ifconfig.me..."

    # Obtención de datos con timeout
    IP=$(timeout 5 curl -s https://ifconfig.me/ip 2>/dev/null || echo "unknown")
    UA=$(timeout 5 curl -s https://ifconfig.me/ua 2>/dev/null || echo "unknown")
    ASN=$(timeout 5 curl -s https://ifconfig.me/asn 2>/dev/null || echo "unknown")
    HOST=$(timeout 5 curl -s https://ifconfig.me/host 2>/dev/null || echo "unknown")
    CITY=$(timeout 5 curl -s https://ifconfig.me/city 2>/dev/null || echo "unknown")
    COUNTRY=$(timeout 5 curl -s https://ifconfig.me/country 2>/dev/null || echo "unknown")

    if [ "$IP" != "unknown" ]; then
        log "[✔] IP pública: $IP"
        log "[✔] ASN: $ASN"
        log "[✔] Ubicación: $CITY, $COUNTRY"
        log "[✔] Hostname: $HOST"

        # Función para verificar IP privada
        is_private_ip() {
            local ip=$1
            if [[ $ip =~ ^10\. ]] || 
               [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || 
               [[ $ip =~ ^192\.168\. ]] || 
               [[ $ip =~ ^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]]; then
                return 0  # Es privada
            else
                return 1  # No es privada
            fi
        }

        # Obtener IPs locales
        IP_LOCAL=$(ip -4 addr show 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1)

        # Verificar si la IP pública está en las IPs locales
        found=0
        for ip in $IP_LOCAL; do
            if [ "$ip" = "$IP" ]; then
                found=1
                break
            fi
        done

        if [ $found -eq 0 ]; then
            # Si no encontramos la IP pública en las locales, verificar si todas las locales son privadas
            all_private=1
            for ip in $IP_LOCAL; do
                if ! is_private_ip "$ip"; then
                    all_private=0
                    break
                fi
            done

            if [ $all_private -eq 1 ]; then
                log "[⚠] Posible CGNAT detectado: IP pública ($IP) no coincide con IPs locales (todas privadas)."
            else
                log "[ℹ] IP pública ($IP) no coincide con IPs locales, pero hay IPs locales públicas. Podría ser una red compleja."
            fi
        else
            log "[✔] IP pública coincide con una IP local. No es CGNAT."
        fi

        # Detección de cambios de IP
        log "[+] Verificando estabilidad de IP..."
        IP1="$IP"
        sleep 1
        IP2=$(timeout 5 curl -s https://ifconfig.me/ip 2>/dev/null || echo "unknown")
        sleep 1
        IP3=$(timeout 5 curl -s https://ifconfig.me/ip 2>/dev/null || echo "unknown")

        if [[ "$IP1" != "$IP2" || "$IP2" != "$IP3" ]]; then
            log "[⚠] Cambios rápidos en IP detectados — posible balanceo/proxy/VPN"
        else
            log "[✔] IP estable"
        fi

        # Análisis de ASN
        if echo "$ASN" | grep -qiE "amazon|google|digitalocean|ovh|linode|azure|choopa|contabo|hetzner"; then
            log "[⚠] IP pertenece a ASN de datacenter — típicamente VPN/servidor"
        fi

        # Detección de ubicaciones sospechosas
        if echo "$CITY" | grep -qiE "Miami|Atlanta|Ashburn|Virginia|Amsterdam|Frankfurt|Zurich|Singapore|Tokyo"; then
            log "[⚠] Ciudad típica de salida VPN/CDN: $CITY"
        fi

        # Análisis de User-Agent
        if [[ "$UA" == *"curl"* ]]; then
            log "[⚠] User-Agent: curl — cualquier servidor sabrá que eres un script."
        else
            log "[✔] User-Agent parece normal."
        fi

    else
        log "[⚠] No se pudo obtener información externa"
    fi
else
    log "[ℹ] Sin conexión a internet - omitiendo análisis externo"
fi

# ================================
# 6. PROCESOS SOSPECHOSOS
# ================================
log
log "==============================================="
log " 6. DETECCIÓN DE SERVICIOS SOSPECHOSOS"
log "==============================================="

log "[+] Buscando procesos que abren IPv6..."

PROCS=$(ss -tulpen 2>/dev/null | grep "tcp6" | awk '{print $NF}' | sed -e 's/users://g' -e 's/[()]//g')

if [ -z "$PROCS" ]; then
    log "[✔] Ningún proceso escucha en IPv6."
else
    log "[⚠] Procesos activos en IPv6:"
    log "$PROCS"
fi

# ================================
# 7. ANÁLISIS DEL FIREWALL
# ================================
log
log "==============================================="
log " 7. ANÁLISIS DEL FIREWALL IPv6"
log "==============================================="

# UFW
if command -v ufw &> /dev/null; then
    log "[+] UFW Status:"
    ufw status 2>/dev/null | grep -i ipv6 | while read line; do
        log "  $line"
    done
else
    log "[ℹ] UFW no instalado"
fi

# IP6Tables
if command -v ip6tables &> /dev/null; then
    log
    log "[+] IP6Tables Rules:"
    sudo ip6tables -L -n -v 2>/dev/null | head -20 | while read line; do
        log "  $line"
    done
else
    log "[ℹ] IP6Tables no disponible"
fi

# NFTables
if command -v nft &> /dev/null; then
    log
    log "[+] NFTables IPv6:"
    sudo nft list ruleset 2>/dev/null | grep -i ip6 | head -10 | while read line; do
        log "  $line"
    done
fi

# ================================
# 8. DETECCIÓN DE MALWARE
# ================================
log
log "==============================================="
log " 8. CHEQUEO DE MALWARE BASADO EN IPv6"
log "==============================================="

MALWARE_PROCS=("kworker" "xmrig" "coinhive" "minerd" "python3 -m http" "nc -l" "socat tcp6" "darkhttpd" "masscan" "zmap" "pwnrig" "cpuminer")

FOUND=0
for sig in "${MALWARE_PROCS[@]}"; do
    if pgrep -f "$sig" >/dev/null 2>&1; then
        log "[⚠] Posible malware detectado: $sig"
        FOUND=1
    fi
done

if [ $FOUND -eq 0 ]; then
    log "[✔] No se detectan procesos maliciosos conocidos."
fi



echo "==============================================="
echo "  DETECCIÓN AVANZADA DE CGNAT"
echo "==============================================="

# Función para verificar si una IP está en rango CGNAT
is_cgnat_ip() {
    local ip=$1
    # Rango CGNAT: 100.64.0.0 - 100.127.255.255 (100.64.0.0/10)
    if [[ $ip =~ ^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]]; then
        return 0
    fi
    return 1
}

# Función para verificar IP privada
is_private_ip() {
    local ip=$1
    if [[ $ip =~ ^10\. ]] || 
       [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || 
       [[ $ip =~ ^192\.168\. ]]; then
        return 0
    fi
    return 1
}

# Función para obtener IP pública
get_public_ip() {
    # Múltiples servicios para verificar consistencia
    local services=(
        "https://ifconfig.me/ip"
        "https://api.ipify.org"
        "https://ident.me"
        "https://ipecho.net/plain"
    )
    
    for service in "${services[@]}"; do
        ip=$(timeout 5 curl -s "$service")
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    echo "unknown"
    return 1
}

# Función para analizar TTL y detectar NAT
analyze_ttl() {
    local target="8.8.8.8"
    local ttl_result=$(ping -c 1 -W 2 $target 2>/dev/null | grep "ttl=" | awk '{print $6}' | cut -d= -f2)
    
    if [ -n "$ttl_result" ]; then
        echo $ttl_result
        return 0
    fi
    echo "unknown"
    return 1
}

echo "[+] Obteniendo información de red..."

# 1. Obtener IPs locales
LOCAL_IPS=$(ip -4 addr show | grep "inet " | awk '{print $2}' | cut -d/ -f1)
PUBLIC_IP=$(get_public_ip)

echo "[✔] IP pública detectada: $PUBLIC_IP"
echo "[✔] IPs locales: $LOCAL_IPS"

# 2. Análisis de CGNAT
CGNAT_DETECTED=0
REASON=""

echo
echo "[+] Realizando análisis CGNAT..."

# Método 1: Verificar si IP pública está en rango CGNAT
if is_cgnat_ip "$PUBLIC_IP"; then
    CGNAT_DETECTED=1
    REASON="IP pública ($PUBLIC_IP) está en rango CGNAT (100.64.0.0/10)"
    echo "[‼] $REASON"
fi

# Método 2: Comparar IP pública con IPs locales
LOCAL_PUBLIC_FOUND=0
for local_ip in $LOCAL_IPS; do
    if [[ "$local_ip" == "$PUBLIC_IP" ]]; then
        LOCAL_PUBLIC_FOUND=1
        break
    fi
done

if [ $LOCAL_PUBLIC_FOUND -eq 0 ]; then
    # Ninguna IP local coincide con la pública
    ALL_LOCAL_PRIVATE=1
    for local_ip in $LOCAL_IPS; do
        if ! is_private_ip "$local_ip"; then
            ALL_LOCAL_PRIVATE=0
            break
        fi
    done
    
    if [ $ALL_LOCAL_PRIVATE -eq 1 ]; then
        CGNAT_DETECTED=1
        REASON="IP pública ($PUBLIC_IP) diferente de IPs locales privadas - CGNAT probable"
        echo "[‼] $REASON"
    fi
else
    echo "[✔] IP pública coincide con IP local - No CGNAT"
fi

# Método 3: Análisis de TTL
TTL=$(analyze_ttl)
if [ "$TTL" != "unknown" ]; then
    echo "[✔] TTL detectado: $TTL"
    # TTL típicos: 64 (Linux), 128 (Windows), 255 (algunos routers)
    # Si el TTL es muy diferente del esperado, podría indicar NAT múltiple
    if [ $TTL -lt 50 ]; then
        echo "[⚠] TTL bajo ($TTL) - posible múltiple NAT (CGNAT + NAT local)"
    fi
fi

# Método 4: Verificar conectividad P2P
echo
echo "[+] Probando conectividad P2P..."
# Intentar conexión directa (esto fallará en CGNAT)
if timeout 5 nc -l -p 9999 2>/dev/null & 
then
    NC_PID=$!
    sleep 1
    # Verificar si el puerto es realmente accesible externamente
    if ! curl -s "http://portcheck.tools:9999" &>/dev/null; then
        echo "[⚠] Puerto no accesible externamente - típico de CGNAT"
        if [ $CGNAT_DETECTED -eq 0 ]; then
            REASON="Puertos no forwardeados - CGNAT posible"
        fi
    else
        echo "[✔] Puerto accesible externamente - menos probable CGNAT"
    fi
    kill $NC_PID 2>/dev/null
fi

# Método 5: Verificar características de ISP conocidos por usar CGNAT
KNOWN_CGNAT_ASN=("AS7922" "AS11351" "AS11404" "AS12271" "AS1668" "AS20115" "AS22773")
KNOWN_CGNAT_IPS=("100.64." "100.65." "100.66." "100.67." "100.68." "100.69." "100.70." "100.71.")

for range in "${KNOWN_CGNAT_IPS[@]}"; do
    if [[ $PUBLIC_IP == $range* ]]; then
        CGNAT_DETECTED=1
        REASON="IP en rango CGNAT conocido del ISP"
        echo "[‼] $REASON"
        break
    fi
done

# Método 6: Detectar doble NAT
GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1)
if [ -n "$GATEWAY" ]; then
    GATEWAY_OCTET=$(echo $GATEWAY | cut -d. -f1)
    if [ "$GATEWAY_OCTET" = "100" ] || [ "$GATEWAY_OCTET" = "10" ]; then
        echo "[⚠] Gateway en rango privado - posible doble NAT"
    fi
fi

# Resumen final
echo
echo "==============================================="
echo "  RESULTADO DEL ANÁLISIS CGNAT"
echo "==============================================="

if [ $CGNAT_DETECTED -eq 1 ]; then
    echo "[‼] CGNAT DETECTADO: $REASON"
    echo
    echo "Consecuencias:"
    echo "• No puedes hospedar servicios desde tu red"
    echo "• Juegos P2P pueden tener problemas"
    echo "• Conexiones entrantes bloqueadas"
    echo "• Posibles problemas con VoIP/videollamadas"
    echo
    echo "Soluciones:"
    echo "• Usar IPv6 (si está disponible)"
    echo "• Servicio VPN con IP dedicada"
    echo "• Tunnel services (ngrok, Cloudflare Tunnel)"
    echo "• Solicitar IP pública a tu ISP (puede tener costo)"
else
    echo "[✔] NO se detectó CGNAT - tienes IP pública directa"
    echo
    echo "Ventajas:"
    echo "• Puedes hospedar servicios"
    echo "• Mejor conectividad P2P"
    echo "• Menos problemas con aplicaciones en tiempo real"
fi

# Información adicional del ISP
echo
echo "==============================================="
echo "  INFORMACIÓN ADICIONAL"
echo "==============================================="

# Obtener información del ISP
if command -v whois &>/dev/null && [ "$PUBLIC_IP" != "unknown" ]; then
    echo "[+] Obteniendo información del ISP..."
    ISP_INFO=$(whois "$PUBLIC_IP" | grep -i "netname\|descr\|country\|origin" | head -5)
    if [ -n "$ISP_INFO" ]; then
        echo "Información del ISP:"
        echo "$ISP_INFO"
    fi
fi

# Verificar IPv6 como alternativa
echo
echo "[+] Estado IPv6:"
IPV6_GLOBAL=$(ip -6 addr show | grep "scope global" | wc -l)
if [ $IPV6_GLOBAL -gt 0 ]; then
    echo "[✔] IPv6 global disponible - alternativa a CGNAT IPv4"
    echo "    Puedes usar IPv6 para servicios y conectividad directa"
else
    echo "[⚠] IPv6 no detectado - dependes completamente de IPv4"
fi

echo
echo "Análisis CGNAT completado: $(date)"
# ================================
# 9. GENERACIÓN DE REPORTE JSON
# ================================
log
log "==============================================="
log " 9. GENERANDO REPORTE COMPLETO"
log "==============================================="

# Preparar datos para JSON
ANOMALIES=()

if [ ${#OPEN_CRITICAL_PORTS[@]} -gt 0 ]; then
    ANOMALIES+=("Puertos críticos abiertos: ${OPEN_CRITICAL_PORTS[*]}")
fi

if [ -n "$PROCS" ]; then
    ANOMALIES+=("Procesos escuchando en IPv6 detectados")
fi

if [ "$IP" != "unknown" ] && [[ "$ASN" =~ "amazon\|google\|digitalocean" ]]; then
    ANOMALIES+=("IP en ASN de datacenter: $ASN")
fi

# Convertir array a JSON
ANOMALIES_JSON=$(printf '"%s",' "${ANOMALIES[@]}")
ANOMALIES_JSON="[${ANOMALIES_JSON%,}]"

# Crear reporte JSON
cat > "$OUTPUT_FILE" << EOF
{
    "timestamp": "$(date -Iseconds)",
    "ipv6_audit": {
        "global_ipv6": "$GLOBAL_V6",
        "has_temporary_addresses": "$([ -n "$TEMP_V6" ] && echo "true" || echo "false")",
        "open_ports": [$(printf '%s,' "${OPEN_PORTS[@]}" | sed 's/,$//')],
        "open_critical_ports": [$(printf '%s,' "${OPEN_CRITICAL_PORTS[@]}" | sed 's/,$//')],
        "listening_services": "$([ -n "$LISTEN_V6" ] && echo "true" || echo "false")"
    },
    "external_analysis": {
        "public_ip": "$IP",
        "asn": "$ASN",
        "hostname": "$HOST",
        "location": "$CITY, $COUNTRY",
        "user_agent": "$UA"
    },
    "security_analysis": {
        "anomalies": $ANOMALIES_JSON,
        "risk_level": "$(if [ ${#OPEN_CRITICAL_PORTS[@]} -gt 0 ]; then echo "HIGH"; elif [ ${#OPEN_PORTS[@]} -gt 0 ]; then echo "MEDIUM"; else echo "LOW"; fi)",
        "firewall_status": "$(if command -v ufw &>/dev/null || command -v ip6tables &>/dev/null; then echo "ACTIVE"; else echo "INACTIVE"; fi)"
    }
}
EOF

log "[✔] Reporte JSON generado: $OUTPUT_FILE"

# ================================
# 10. CONCLUSIÓN FINAL
# ================================
log
log "==============================================="
log " 10. CONCLUSIÓN DE SEGURIDAD IPv6"
log "==============================================="

if [ ${#OPEN_PORTS[@]} -eq 0 ] && [ -z "$LISTEN_V6" ]; then
    log "[✓] IPv6 SEGURA: Sin exposición externa significativa."
elif [ ${#OPEN_CRITICAL_PORTS[@]} -gt 0 ]; then
    log "[‼] ALTO RIESGO: Puertos críticos expuestos en IPv6."
    log "    Puertos abiertos: ${OPEN_CRITICAL_PORTS[*]}"
else
    log "[!] RIESGO MODERADO: Revisar configuración IPv6."
fi

log
log "[✔] Auditoría avanzada IPv6 completada a las $(date)."


#!/bin/bash

echo "==============================================="
echo "  AUDITORÍA PROFUNDA IPv6 - PUNTOS CRÍTICOS"
echo "==============================================="

# 1. DETECCIÓN DE ROGUE ROUTER ADVERTISEMENTS
echo
echo "1. DETECCIÓN DE ROGUE ROUTERS"
echo "================================"

# Verificar múltiples routers
echo "[+] Buscando múltiples routers en la red..."
current_routers=$(ip -6 route show | grep "default" | awk '{print $3}' | sort -u)
router_count=$(echo "$current_routers" | wc -l)

if [ $router_count -gt 1 ]; then
    echo "  [⚠] Múltiples routers detectados:"
    echo "$current_routers" | while read router; do
        echo "    - $router"
    done
else
    echo "  [✔] Un solo router detectado: $current_routers"
fi

# 2. ANÁLISIS DE DAD (DUPLICATE ADDRESS DETECTION)
echo
echo "2. ESTADO DAD (DUPLICATE ADDRESS DETECTION)"
echo "================================"

if [ -f /proc/sys/net/ipv6/conf/all/dad_transmits ]; then
    dad_transmits=$(cat /proc/sys/net/ipv6/conf/all/dad_transmits)
    echo "  dad_transmits: $dad_transmits"
fi

# 3. INFORMACIÓN DE HOP LIMIT
echo
echo "3. CONFIGURACIÓN HOP LIMIT"
echo "================================"

if [ -f /proc/sys/net/ipv6/conf/all/hop_limit ]; then
    hop_limit=$(cat /proc/sys/net/ipv6/conf/all/hop_limit)
    echo "  hop_limit: $hop_limit"
fi

# 4. DETECCIÓN DE TÚNELES IPv6
echo
echo "4. TÚNELES IPv6 DETECTADOS"
echo "================================"

tunnels=$(ip -6 tunnel show 2>/dev/null)
if [ -n "$tunnels" ]; then
    echo "  [⚠] Túneles IPv6 activos:"
    echo "$tunnels"
else
    echo "  [✔] No hay túneles IPv6 activos"
fi

# 5. ANÁLISIS DE CONECTIVIDAD DUAL-STACK
echo
echo "5. ESTADO DUAL-STACK"
echo "================================"

ipv4_default=$(ip -4 route show default 2>/dev/null | wc -l)
ipv6_default=$(ip -6 route show default 2>/dev/null | wc -l)

echo "  IPv4 default routes: $ipv4_default"
echo "  IPv6 default routes: $ipv6_default"

if [ $ipv4_default -gt 0 ] && [ $ipv6_default -gt 0 ]; then
    echo "  [✔] Dual-stack completamente operativo"
elif [ $ipv6_default -gt 0 ]; then
    echo "  [ℹ] Solo IPv6 disponible"
else
    echo "  [ℹ] Solo IPv4 disponible"
fi

# 6. INFORMACIÓN DE PROTOCOLOS DE ENRUTAMIENTO
echo
echo "6. PROTOCOLOS DE ENRUTAMIENTO IPv6"
echo "================================"

# Verificar si hay protocolos de enrutamiento activos
echo "[+] Tablas de enrutamiento:"
ip -6 rule show | while read rule; do
    echo "  $rule"
done

# 7. ANÁLISIS DE CALIDAD DE SERVICIO (QoS)
echo
echo "7. CONFIGURACIÓN QoS IPv6"
echo "================================"

# Verificar clasificación de tráfico
if tc qdisc show 2>/dev/null | grep -q :; then
    echo "  [ℹ] QoS configurado en el sistema"
    tc -s qdisc show | head -5 | while read line; do
        echo "    $line"
    done
else
    echo "  [ℹ] No hay QoS configurado"
fi

# 8. INFORMACIÓN DE SEGURIDAD AVANZADA
echo
echo "8. SEGURIDAD AVANZADA IPv6"
echo "================================"

# Verificar RA Guard
if [ -f /proc/sys/net/ipv6/conf/all/accept_ra ]; then
    accept_ra=$(cat /proc/sys/net/ipv6/conf/all/accept_ra)
    if [ $accept_ra -eq 0 ]; then
        echo "  [✔] RA Guard activo (accept_ra=0)"
    else
        echo "  [⚠] RA Guard no activo"
    fi
fi

# Verificar si estamos usando extensiones de privacidad
privacy_extensions=$(ip -6 addr show | grep -c "temporary")
if [ $privacy_extensions -gt 0 ]; then
    echo "  [✔] Privacy extensions activas"
else
    echo "  [⚠] Privacy extensions no activas"
fi

echo
echo "==============================================="
echo "  RESUMEN DE SEGURIDAD IPv6"
echo "==============================================="

# Calcular puntuación de seguridad
security_score=0
max_score=8

[ $(ip -6 addr show | grep -c "temporary") -gt 0 ] && ((security_score++))
[ $(cat /proc/sys/net/ipv6/conf/all/accept_ra 2>/dev/null) -eq 0 ] && ((security_score++))
[ $(ip -6 route show default 2>/dev/null | wc -l) -eq 1 ] && ((security_score++))
[ $(ip -6 neigh show | wc -l) -lt 500 ] && ((security_score++))
[ -z "$(ip -6 tunnel show 2>/dev/null)" ] && ((security_score++))
[ $(ip -6 addr show | grep "global" | awk '{print $2}' | sed 's/\/.*//' | sort | uniq -d | wc -l) -eq 0 ] && ((security_score++))
[ $(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null) -eq 0 ] && ((security_score++))
[ $(cat /proc/sys/net/ipv6/conf/all/accept_redirects 2>/dev/null) -eq 0 ] && ((security_score++))

echo "Puntuación de seguridad: $security_score/$max_score"

if [ $security_score -ge 6 ]; then
    echo "✅ CONFIGURACIÓN SEGURA"
elif [ $security_score -ge 4 ]; then
    echo "⚠️  CONFIGURACIÓN MODERADA"
else
    echo "❌ CONFIGURACIÓN DE RIESGO"
fi



# IPv6 Advanced Security & Anomaly Audit

### Auditoría automática de seguridad en IPv6 (Linux)

Este proyecto entrega un **script de auditoría IPv6 avanzado**, diseñado para usuarios que quieren revisar si su equipo está **expuesto**, si tiene **puertos abiertos**, si está detrás de **CGNAT**, si algún proceso está escuchando sin permiso, y si existe actividad sospechosa relacionada con conexiones IPv6.

El informe se genera en consola y también se guarda en un archivo JSON para revisión posterior.

---

## 🚀 Características principales

* **Detección de direcciones IPv6 globales y temporales**
  Identifica si el dispositivo está expuesto públicamente y si la privacidad mejorada está activada.

* **Escaneo de servicios que escuchan en IPv6 (TCP/UDP)**
  Muestra qué programas están recibiendo conexiones desde internet.

* **Análisis de puertos críticos**
  Verifica si puertos sensibles están expuestos (SSH, bases de datos, web, etc.).

* **Escaneo ampliado de puertos estratégicos**
  Escaneo rápido de puertos 1–1024 más puertos de riesgo frecuente.

* **Análisis externo avanzado**
  Obtiene IP pública, ASN, ciudad, hostname, estabilidad y detección de posible VPN o CGNAT.

* **Detección de procesos sospechosos**
  Revisa patrones comunes de malware que utiliza IPv6.

* **Revisión de firewall IPv6**
  Soporte automático para:

  * UFW
  * ip6tables
  * nftables

* **Detección avanzada de CGNAT**
  Usa IP pública + TTL + rangos + consistencia de servicios externos.

---

## 📦 Requisitos

El script detecta dependencias automáticamente, pero idealmente el sistema debería contar con:

* `bash`
* `curl`
* `ss`
* `ip`
* `nft` (opcional)
* `ufw` (opcional)
* `netcat`/`nc` (opcional)

---

## 📥 Instalación

```bash
git clone https://github.com/TU-USUARIO/ipv6-anomaly-seeker.git
cd ipv6-anomaly-seeker
chmod +x ipv6_anomaly_seeker.sh
```

---

## ▶️ Uso

Ejecuta el script:

```bash
./ipv6_anomaly_seeker.sh
```

El reporte JSON se generará automáticamente con nombre:

```
ipv6_audit_report_YYYYMMDD_HHMMSS.json
```

---

## 🛡️ ¿Qué revela este escaneo?

Esta auditoría puede indicar:

* Si tu equipo está expuesto a internet mediante IPv6
* Puertos abiertos accesibles desde el exterior
* Servicios escuchando sin que lo supieras
* Si estás bajo **CGNAT** o tienes IP pública real
* Posibles indicadores de:

  * VPN
  * Proxies
  * Balanceo de carga
* Configuración del firewall IPv6
* Señales comunes de malware o minería no autorizada

---

## 📄 Ejemplo de salida

**Conexión global detectada**

* IPv6 global presente
* Puertos abiertos: ninguno
* Procesos sospechosos: no encontrados
* Firewall: activo
* IP pública estable

---

## ⭐ Mejores prácticas de mitigación

* Activar IPv6 Privacy Extensions
* Limitar servicios que escuchen en IPv6 (sshd, web, DB)
* Habilitar firewall IPv6 (UFW o nftables)
* Evitar exponer bases de datos a internet
* Usar VPN si no quieres revelar IP real
* Monitorear procesos que abran sockets IPv6

---

## 📬 Contribuciones

¡Pull requests bienvenidos!
También puedes abrir un issue para sugerir mejoras o nuevas funciones.

---

## 📝 Licencia

MIT — Libre para modificar y distribuir.

---

¿Quieres que también genere el **logo del proyecto**, **capturas**, o un **badge de GitHub Actions** para automatizar pruebas? ¿Te lo preparo? ¿️
Aquí tienes un **README.md listo para subir a GitHub**, claro, moderno y sin tecnicismos innecesarios. Presenta el script como una herramienta profesional, robusta y fácil de entender.

---

# IPv6 Advanced Security & Anomaly Audit

### Auditoría automática de seguridad en IPv6 (Linux)

Este proyecto entrega un **script de auditoría IPv6 avanzado**, diseñado para usuarios que quieren revisar si su equipo está **expuesto**, si tiene **puertos abiertos**, si está detrás de **CGNAT**, si algún proceso está escuchando sin permiso, y si existe actividad sospechosa relacionada con conexiones IPv6.

El informe se genera en consola y también se guarda en un archivo JSON para revisión posterior.

---

## 🚀 Características principales

* **Detección de direcciones IPv6 globales y temporales**
  Identifica si el dispositivo está expuesto públicamente y si la privacidad mejorada está activada.

* **Escaneo de servicios que escuchan en IPv6 (TCP/UDP)**
  Muestra qué programas están recibiendo conexiones desde internet.

* **Análisis de puertos críticos**
  Verifica si puertos sensibles están expuestos (SSH, bases de datos, web, etc.).

* **Escaneo ampliado de puertos estratégicos**
  Escaneo rápido de puertos 1–1024 más puertos de riesgo frecuente.

* **Análisis externo avanzado**
  Obtiene IP pública, ASN, ciudad, hostname, estabilidad y detección de posible VPN o CGNAT.

* **Detección de procesos sospechosos**
  Revisa patrones comunes de malware que utiliza IPv6.

* **Revisión de firewall IPv6**
  Soporte automático para:

  * UFW
  * ip6tables
  * nftables

* **Detección avanzada de CGNAT**
  Usa IP pública + TTL + rangos + consistencia de servicios externos.

---

## 📦 Requisitos

El script detecta dependencias automáticamente, pero idealmente el sistema debería contar con:

* `bash`
* `curl`
* `ss`
* `ip`
* `nft` (opcional)
* `ufw` (opcional)
* `netcat`/`nc` (opcional)

---

## 📥 Instalación

```bash
git clone https://github.com/TU-USUARIO/ipv6-anomaly-seeker.git
cd ipv6-anomaly-seeker
chmod +x ipv6_anomaly_seeker.sh
```

---

## ▶️ Uso

Ejecuta el script:

```bash
./ipv6_anomaly_seeker.sh
```

El reporte JSON se generará automáticamente con nombre:

```
ipv6_audit_report_YYYYMMDD_HHMMSS.json
```

---

## 🛡️ ¿Qué revela este escaneo?

Esta auditoría puede indicar:

* Si tu equipo está expuesto a internet mediante IPv6
* Puertos abiertos accesibles desde el exterior
* Servicios escuchando sin que lo supieras
* Si estás bajo **CGNAT** o tienes IP pública real
* Posibles indicadores de:

  * VPN
  * Proxies
  * Balanceo de carga
* Configuración del firewall IPv6
* Señales comunes de malware o minería no autorizada

---

## 📄 Ejemplo de salida

**Conexión global detectada**

* IPv6 global presente
* Puertos abiertos: ninguno
* Procesos sospechosos: no encontrados
* Firewall: activo
* IP pública estable

---

## ⭐ Mejores prácticas de mitigación

* Activar IPv6 Privacy Extensions
* Limitar servicios que escuchen en IPv6 (sshd, web, DB)
* Habilitar firewall IPv6 (UFW o nftables)
* Evitar exponer bases de datos a internet
* Usar VPN si no quieres revelar IP real
* Monitorear procesos que abran sockets IPv6

---

## 📬 Contribuciones

¡Pull requests bienvenidos!
También puedes abrir un issue para sugerir mejoras o nuevas funciones.

---

## 📝 Licencia

MIT — Libre para modificar y distribuir.

---

cd ipv6-anomaly-seeker
chmod +x ipv6_audit.sh
```

---

## ▶️ Uso

Ejecuta el script:

```bash
./ipv6_anomaly_seeker.sh
```

El reporte JSON se generará automáticamente con nombre:

```
ipv6_audit_report_YYYYMMDD_HHMMSS.json
```

---

## 🛡️ ¿Qué revela este escaneo?

Esta auditoría puede indicar:

* Si tu equipo está expuesto a internet mediante IPv6
* Puertos abiertos accesibles desde el exterior
* Servicios escuchando sin que lo supieras
* Si estás bajo **CGNAT** o tienes IP pública real
* Posibles indicadores de:

  * VPN
  * Proxies
  * Balanceo de carga
* Configuración del firewall IPv6
* Señales comunes de malware o minería no autorizada

---

## 📄 Ejemplo de salida

**Conexión global detectada**

* IPv6 global presente
* Puertos abiertos: ninguno
* Procesos sospechosos: no encontrados
* Firewall: activo
* IP pública estable

---

## ⭐ Mejores prácticas de mitigación

* Activar IPv6 Privacy Extensions
* Limitar servicios que escuchen en IPv6 (sshd, web, DB)
* Habilitar firewall IPv6 (UFW o nftables)
* Evitar exponer bases de datos a internet
* Usar VPN si no quieres revelar IP real
* Monitorear procesos que abran sockets IPv6


---

¿Quieres que también genere el **logo del proyecto**, **capturas**, o un **badge de GitHub Actions** para automatizar pruebas? ¿Te lo preparo? ¿️

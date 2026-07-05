import { useState, useMemo, useRef, useEffect } from "react";

// ─── Icons (inline SVG to avoid dependency issues) ───
const Icons = {
  Shield: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  Server: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>,
  Alert: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  Info: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>,
  Check: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>,
  Search: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>,
  X: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>,
  ChevDown: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"/></svg>,
  ChevRight: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="9 18 15 12 9 6"/></svg>,
  Package: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="16.5" y1="9.4" x2="7.5" y2="4.21"/><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>,
  External: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>,
  Moon: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>,
  Sun: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>,
  Wrench: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg>,
  Link: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>,
  ArrowLeft: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>,
  Gpu: (p) => <svg xmlns="http://www.w3.org/2000/svg" width={p.size||16} height={p.size||16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>,
};

// ─── Tooltip component ───
function Tip({ text, children }) {
  const [show, setShow] = useState(false);
  const [pos, setPos] = useState({ x: 0, y: 0 });
  const ref = useRef(null);

  const handleEnter = (e) => {
    const rect = e.currentTarget.getBoundingClientRect();
    setPos({ x: rect.left + rect.width / 2, y: rect.top - 8 });
    setShow(true);
  };

  return (
    <span className="tip-wrap" onMouseEnter={handleEnter} onMouseLeave={() => setShow(false)} ref={ref}>
      {children}
      {show && (
        <span className="tip-bubble" style={{ left: 0, bottom: '100%', marginBottom: 6 }}>
          {text}
        </span>
      )}
    </span>
  );
}

function InfoIcon({ text }) {
  return (
    <Tip text={text}>
      <span className="info-dot"><Icons.Info size={13} /></span>
    </Tip>
  );
}

// ─── Data ───
const MACHINES = {
  "monitor-host": { role: "Monitor SOC", color: "#6c72ff", icon: "🖥️", gpu: false },
  "prod-1":  { role: "Producción", color: "#ff3b5c", icon: "🔴", gpu: true },
  "staging-1": { role: "Staging", color: "#ff9f43", icon: "🟠", gpu: true },
  "app-prod-1":    { role: "Aplicación Prod", color: "#34d399", icon: "🟢", gpu: false },
  "app-dev-1":{ role: "Aplicación Dev", color: "#4d9fff", icon: "🔵", gpu: false },
};

const VULNS = [
  {
    id: "CVE-2026-22184", severity: "CRITICAL", pkg: "zlib", type: "Sistema (Alpine)",
    installed: "1.3.1-r2", fixed: "1.3.2-r0",
    title: "Ejecución de código arbitrario en zlib",
    what: "Un atacante puede ejecutar código malicioso en el servidor enviando datos comprimidos especialmente diseñados. Zlib es una librería de compresión que usan muchos programas internamente.",
    why: "Es crítico porque permite tomar control del servidor de forma remota, sin necesitar autenticación. Cualquier servicio que descomprima datos (descargas, APIs, archivos) está expuesto.",
    howToFix: "Actualizar la imagen base Alpine. En el Dockerfile, cambiar 'FROM alpine:3.19' a 'FROM alpine:3.20' o ejecutar 'apk upgrade zlib' en el build.",
    images: ["your-org/dns", "grafana/loki", "your-org/app-server"],
    machines: ["monitor-host", "app-prod-1"],
    dependsOn: ["Muchos programas usan zlib internamente, pero la actualización es compatible"],
    hasConflict: false, status: "pending",
  },
  {
    id: "CVE-2026-32136", severity: "CRITICAL", pkg: "tu DNS server", type: "Aplicación (Go)",
    installed: "v0.107.72", fixed: "0.107.73",
    title: "Salto de autenticación en tu DNS server",
    what: "Un atacante puede saltarse la pantalla de login de tu DNS server y acceder al panel de administración sin credenciales, usando un tipo especial de conexión HTTP/2.",
    why: "Es crítico porque tu DNS gestiona el DNS interno de toda la VPN. Si alguien accede, puede redirigir tráfico, ver qué dominios consultan los equipos y bloquear servicios.",
    howToFix: "Actualizar tu DNS server a v0.107.73. En monitor-host: 'docker pull your-org/dns:v0.107.73' y recrear el contenedor.",
    images: ["your-org/dns"],
    machines: ["monitor-host"],
    dependsOn: [],
    hasConflict: false, status: "pending",
  },
  {
    id: "CVE-2025-15467", severity: "CRITICAL", pkg: "OpenSSL (libcrypto3)", type: "Sistema (Alpine)",
    installed: "3.3.5-r0", fixed: "3.3.6-r0",
    title: "Ejecución remota de código en OpenSSL",
    what: "Un fallo en el proceso de conexión segura (TLS handshake) permite que un atacante ejecute código en el servidor o tire el servicio. OpenSSL es la librería que gestiona TODAS las conexiones HTTPS.",
    why: "Es crítico porque afecta a los servicios de producción (API, Agent, Webhooks). Cualquier conexión HTTPS que reciban estos servicios puede ser usada para el ataque.",
    howToFix: "En el Dockerfile de los servicios Python, añadir 'RUN apk upgrade --no-cache libcrypto3 libssl3 openssl' antes del CMD. Rebuild y deploy.",
    images: ["registry.example.com/your-api", "registry.example.com/your-agent", "registry.example.com/your-webhooks"],
    machines: ["prod-1", "staging-1"],
    dependsOn: ["libssl3", "openssl", "python3", "curl — todos compatibles con la versión 3.3.6"],
    hasConflict: false, status: "pending",
  },
  {
    id: "CVE-2025-6965", severity: "CRITICAL", pkg: "SQLite", type: "Sistema (Alpine)",
    installed: "3.45.3-r2", fixed: "3.45.3-r3",
    title: "Desbordamiento de entero en SQLite",
    what: "Un error de cálculo interno en SQLite puede corromper la memoria del programa. SQLite se usa dentro de Python y muchas aplicaciones para almacenamiento local.",
    why: "Es crítico porque si un atacante puede hacer que la aplicación procese una base de datos SQLite maliciosa, puede ejecutar código arbitrario en el servidor.",
    howToFix: "Añadir 'RUN apk upgrade --no-cache sqlite-libs' en el Dockerfile. Es un patch menor (3.45.3-r2 → r3), no rompe nada.",
    images: ["registry.example.com/your-api"],
    machines: ["prod-1", "staging-1"],
    dependsOn: ["python3 — compatible, es solo un patch de seguridad"],
    hasConflict: false, status: "pending",
  },
  {
    id: "CVE-2023-45853", severity: "CRITICAL", pkg: "zlib1g", type: "Sistema (Debian)",
    installed: "1:1.2.13.dfsg-1", fixed: null,
    title: "Desbordamiento de buffer en zlib (Debian)",
    what: "Similar al CVE de zlib en Alpine pero en paquetes Debian. Permite ejecución de código a través de archivos ZIP maliciosos.",
    why: "Es crítico por el impacto, pero no tiene solución disponible todavía en los repositorios de Debian. Hay que monitorizar hasta que salga el parche.",
    howToFix: "Sin solución disponible. Debian no ha publicado un parche. Monitorizar en https://security-tracker.debian.org/.",
    images: ["your-org/crm"],
    machines: ["monitor-host"],
    dependsOn: ["libpng16-16", "libfreetype6"],
    hasConflict: false, status: "monitoring", noFix: true,
  },
  {
    id: "CVE-2026-25896", severity: "CRITICAL", pkg: "fast-xml-parser", type: "Librería (npm)",
    installed: "5.2.5", fixed: "5.3.5",
    title: "Inyección de código (XSS) en fast-xml-parser",
    what: "Un atacante puede inyectar código JavaScript malicioso a través de documentos XML que procese la aplicación. fast-xml-parser convierte XML a objetos JavaScript.",
    why: "Es crítico porque si la aplicación muestra datos de XML procesado en una interfaz web, el código malicioso se ejecutaría en el navegador del usuario.",
    howToFix: "Actualizar fast-xml-parser: 'npm install fast-xml-parser@5.3.5'. Es un patch, compatible con la versión actual.",
    images: ["your-org/crm", "your-org/sip-gateway"],
    machines: ["monitor-host", "app-prod-1"],
    dependsOn: [],
    hasConflict: false, status: "pending",
  },
  {
    id: "CVE-2024-41110", severity: "CRITICAL", pkg: "Docker Engine (moby)", type: "Aplicación (Go)",
    installed: "v26.1.4", fixed: "26.1.5",
    title: "Fallo de autorización en Docker Engine",
    what: "Un fallo en el plugin de autorización de Docker permite saltarse controles de acceso si se envía una petición API con cuerpo vacío.",
    why: "Es crítico porque permite a usuarios sin permisos ejecutar operaciones privilegiadas en Docker, como crear contenedores con acceso al host.",
    howToFix: "Actualizar la imagen de tu CRM que incluye esta versión de Docker. Contactar con el equipo de tu CRM.",
    images: ["your-org/crm"],
    machines: ["monitor-host"],
    dependsOn: [],
    hasConflict: false, status: "pending",
  },
  // HIGH
  {
    id: "CVE-2025-69419", severity: "HIGH", pkg: "OpenSSL (libcrypto3)", type: "Sistema (Alpine)",
    installed: "3.3.5-r0", fixed: "3.3.6-r0",
    title: "Escritura fuera de límites en PKCS#12",
    what: "Un error al procesar certificados en formato PKCS#12 puede permitir ejecutar código arbitrario. PKCS#12 es el formato estándar para certificados digitales (.p12, .pfx).",
    why: "Es alto porque requiere que el servidor procese un certificado malicioso, lo cual es menos probable que una conexión HTTPS normal, pero sigue siendo peligroso.",
    howToFix: "Se arregla con la misma actualización que CVE-2025-15467: 'apk upgrade libcrypto3 libssl3 openssl'.",
    images: ["registry.example.com/your-api", "registry.example.com/your-agent"],
    machines: ["prod-1", "staging-1"],
    dependsOn: ["libssl3", "openssl — compatible"],
    hasConflict: false, status: "pending",
  },
  {
    id: "CVE-2026-26007", severity: "HIGH", pkg: "cryptography", type: "Librería (Python)",
    installed: "46.0.3", fixed: "46.0.5",
    title: "Ataque de subgrupo por falta de validación",
    what: "La librería 'cryptography' de Python no valida correctamente ciertos parámetros criptográficos, lo que permite ataques que debilitan el cifrado de las comunicaciones.",
    why: "Es alto porque afecta a la API de producción. Un atacante sofisticado podría debilitar el cifrado de las conexiones del servidor.",
    howToFix: "En requirements.txt, cambiar 'cryptography==46.0.3' a 'cryptography>=46.0.5'. Rebuild de la imagen.",
    images: ["registry.example.com/your-api"],
    machines: ["prod-1"],
    dependsOn: ["paramiko", "pyOpenSSL — compatibles con 46.0.5"],
    hasConflict: false, status: "pending",
  },
  {
    id: "CVE-2026-23949", severity: "HIGH", pkg: "jaraco.context", type: "Librería (Python)",
    installed: "5.3.0", fixed: "6.1.0",
    title: "Traversal de directorios en archivos tar",
    what: "Un archivo tar malicioso puede escribir fuera del directorio esperado, permitiendo sobrescribir archivos del sistema.",
    why: "Es alto porque si algún servicio procesa archivos tar (backups, uploads), un archivo malicioso podría sobrescribir archivos críticos.",
    howToFix: "⚠️ CONFLICTO: La versión 6.x requiere Python 3.12+, pero las imágenes usan Python 3.11. Hay que esperar a que your-app migre a Python 3.12 o buscar un backport.",
    images: ["registry.example.com/your-api"],
    machines: ["prod-1", "staging-1"],
    dependsOn: ["jaraco.text", "keyring"],
    hasConflict: true,
    conflictDetail: {
      problem: "jaraco.context 6.x necesita Python 3.12 o superior",
      current: "Las imágenes de la aplicación usan Python 3.11",
      consequence: "Si actualizas, la aplicación no arranca porque Python 3.11 no tiene las APIs que necesita jaraco.context 6.x",
      recommendation: "Esperar a la migración a Python 3.12 o pinear jaraco.context==5.3.0 y aceptar el riesgo temporalmente"
    },
    status: "conflict",
  },
  {
    id: "CVE-2025-66418", severity: "HIGH", pkg: "urllib3", type: "Librería (Python)",
    installed: "2.5.0", fixed: "2.6.0",
    title: "Agotamiento de recursos por descompresión infinita",
    what: "Un servidor malicioso puede enviar respuestas comprimidas que se descomprimen infinitamente, consumiendo toda la memoria del servidor hasta que se cae.",
    why: "Es alto porque urllib3 es la librería que usan requests y botocore (AWS) para hacer peticiones HTTP. Si cualquier API externa devuelve una respuesta maliciosa, el servicio se cae.",
    howToFix: "⚠️ CONFLICTO: urllib3 2.6.0 cambia cómo funcionan los proxies. botocore (AWS SDK) puede fallar con ciertas configuraciones de proxy.",
    images: ["registry.example.com/your-api", "registry.example.com/your-webhooks"],
    machines: ["prod-1", "staging-1"],
    dependsOn: ["requests", "botocore (AWS SDK)"],
    hasConflict: true,
    conflictDetail: {
      problem: "urllib3 2.6.0 elimina soporte para configuraciones legacy de proxy",
      current: "botocore usa urllib3 internamente para conectar con AWS (S3, etc.)",
      consequence: "Si usáis proxy HTTP para conectar a AWS, las operaciones de S3 (backups, archivos) pueden fallar silenciosamente",
      recommendation: "Probar en staging primero. Si no usáis proxy HTTP para AWS, la actualización es segura. Verificar con: 'python -c \"import botocore; print(botocore.__version__)\"'"
    },
    status: "conflict",
  },
  {
    id: "CVE-2026-24049", severity: "HIGH", pkg: "wheel", type: "Librería (Python)",
    installed: "0.45.1", fixed: "0.46.2",
    title: "Escalada de privilegios con paquetes wheel maliciosos",
    what: "Un paquete .whl (formato de distribución de Python) malicioso puede ejecutar código con permisos elevados durante la instalación.",
    why: "Es alto pero el riesgo real es bajo en producción — solo afecta durante el build de las imágenes Docker, no en runtime. Un atacante tendría que envenenar un paquete en PyPI.",
    howToFix: "Actualizar wheel en el Dockerfile: 'pip install --upgrade wheel>=0.46.2'. No tiene dependencias conflictivas.",
    images: ["registry.example.com/your-api", "registry.example.com/your-agent"],
    machines: ["prod-1", "staging-1"],
    dependsOn: [],
    hasConflict: false, status: "pending",
  },
  {
    id: "CVE-2025-64756", severity: "HIGH", pkg: "glob", type: "Librería (npm)",
    installed: "10.4.5", fixed: "11.1.0",
    title: "Inyección de comandos por nombres de archivo maliciosos",
    what: "La librería glob (busca archivos por patrones) puede ejecutar comandos del sistema si procesa nombres de archivo especialmente diseñados.",
    why: "Es alto porque si la aplicación busca archivos con nombres que vienen de input del usuario, un nombre malicioso puede ejecutar comandos en el servidor.",
    howToFix: "⚠️ CONFLICTO: glob 11.x tiene cambios de API grandes. rimraf y fast-glob no son compatibles con glob 11.",
    images: ["your-org/crm", "your-org/sip-gateway"],
    machines: ["monitor-host", "app-prod-1"],
    dependsOn: ["rimraf", "fast-glob"],
    hasConflict: true,
    conflictDetail: {
      problem: "glob 11.x cambia completamente su API pública",
      current: "rimraf 5.x y fast-glob dependen de glob 10.x",
      consequence: "Si actualizas glob a 11.x, rimraf y fast-glob dejan de funcionar, rompiendo operaciones de archivos en tu CRM y tu SIP gateway",
      recommendation: "Esperar a que rimraf publique una versión compatible con glob 11, o aplicar el parche de glob 10.5.0 si existe"
    },
    status: "conflict",
  },
  {
    id: "CVE-2026-23745", severity: "HIGH", pkg: "tar", type: "Librería (npm)",
    installed: "6.2.1", fixed: "7.5.3",
    title: "Sobreescritura de archivos por symlink poisoning",
    what: "Un archivo .tar malicioso puede crear enlaces simbólicos que apuntan fuera del directorio de extracción, permitiendo sobrescribir cualquier archivo del sistema.",
    why: "Es alto porque afecta a npm (que usa tar para instalar paquetes). Un paquete malicioso en npm podría sobrescribir archivos del contenedor.",
    howToFix: "⚠️ CONFLICTO: tar 7.x es un cambio de versión mayor. npm incluye su propia copia de tar que puede no ser compatible.",
    images: ["your-org/crm"],
    machines: ["monitor-host"],
    dependsOn: ["npm", "node-gyp"],
    hasConflict: true,
    conflictDetail: {
      problem: "tar 7.x es una versión mayor con cambios de API",
      current: "npm incluye tar como dependencia interna con una versión específica",
      consequence: "Forzar tar 7.x puede romper la instalación de paquetes npm dentro del contenedor",
      recommendation: "No actualizar manualmente. Esperar a una nueva versión de npm que incluya tar 7.x"
    },
    status: "conflict",
  },
  {
    id: "CVE-2026-0861", severity: "HIGH", pkg: "libc-bin (glibc)", type: "Sistema (Debian)",
    installed: "2.36-9+deb12u13", fixed: null,
    title: "Corrupción de memoria en glibc",
    what: "Un error en la función de asignación de memoria de glibc puede corromper la memoria del proceso. glibc es la librería C básica del sistema — todos los programas la usan.",
    why: "Es alto y sin solución disponible. Debian no ha publicado parche. El riesgo real depende de si algún programa del contenedor usa memalign con valores grandes.",
    howToFix: "Sin solución disponible. Monitorizar actualizaciones de Debian.",
    images: ["your-org/crm"],
    machines: ["monitor-host"],
    dependsOn: ["libc6 — todo el sistema depende de esto"],
    hasConflict: false, status: "monitoring", noFix: true,
  },
  {
    id: "CVE-2025-31133", severity: "HIGH", pkg: "runc", type: "Aplicación (Go)",
    installed: "v1.1.13", fixed: "1.2.8",
    title: "Escape de contenedor por condición de carrera en montajes",
    what: "Un contenedor malicioso puede escapar de su aislamiento y acceder al sistema host explotando una condición de carrera durante el montaje de directorios.",
    why: "Es alto porque un escape de contenedor significa que un atacante dentro de un contenedor puede acceder al host y a otros contenedores.",
    howToFix: "Actualizar runc en el host. En monitor-host: 'sudo apt update && sudo apt install -y runc' o actualizar Docker Engine completo.",
    images: ["your-org/crm"],
    machines: ["monitor-host"],
    dependsOn: [],
    hasConflict: false, status: "pending",
  },
  // MEDIUM
  {
    id: "CVE-2026-30827", severity: "MEDIUM", pkg: "express-rate-limit", type: "Librería (npm)",
    installed: "8.2.1", fixed: "8.2.2",
    title: "Denegación de servicio para usuarios IPv4",
    what: "El rate limiter no agrupa correctamente las direcciones IPv4 mapeadas como IPv6, permitiendo que un atacante bypass el límite de peticiones.",
    why: "Es medio porque requiere que el atacante conozca la configuración del rate limiter y solo afecta a la disponibilidad, no a datos.",
    howToFix: "Actualizar express-rate-limit: 'npm install express-rate-limit@8.2.2'. Es un patch, totalmente compatible.",
    images: ["your-org/sip-gateway"],
    machines: ["app-prod-1"],
    dependsOn: [],
    hasConflict: false, status: "pending",
  },
  {
    id: "CVE-2026-2359", severity: "MEDIUM", pkg: "multer", type: "Librería (npm)",
    installed: "2.0.2", fixed: "2.1.0",
    title: "Denegación de servicio por conexiones de upload abandonadas",
    what: "Si un usuario empieza a subir un archivo y abandona la conexión, multer no libera los recursos correctamente, acumulando memoria hasta que el servicio se cae.",
    why: "Es medio porque solo afecta a la disponibilidad del servicio de subida de archivos, no a datos ni acceso.",
    howToFix: "Actualizar multer: 'npm install multer@2.1.0'. Revisar que el API de subida de archivos sigue funcionando.",
    images: ["your-org/sip-gateway"],
    machines: ["app-prod-1"],
    dependsOn: [],
    hasConflict: false, status: "pending",
  },
];

const SEV = {
  CRITICAL: { color: "#dc2645", bg: "#dc264512", bgSolid: "#fef2f2", label: "Crítico", darkColor: "#ff3b5c", darkBg: "#ff3b5c18" },
  HIGH:     { color: "#e05520", bg: "#e0552012", bgSolid: "#fff7ed", label: "Alto", darkColor: "#ff6b35", darkBg: "#ff6b3518" },
  MEDIUM:   { color: "#b45309", bg: "#b4530912", bgSolid: "#fffbeb", label: "Medio", darkColor: "#ffb020", darkBg: "#ffb02018" },
  LOW:      { color: "#2d7dd2", bg: "#2d7dd212", bgSolid: "#eff6ff", label: "Bajo", darkColor: "#4d9fff", darkBg: "#4d9fff18" },
};

const TABS = [
  { id: "machines", label: "Máquinas", tip: "Vista por servidor. Haz click en una máquina para ver sus vulnerabilidades." },
  { id: "action", label: "Actuar", tip: "Vulnerabilidades que tienen solución disponible y se pueden arreglar ahora." },
  { id: "monitor", label: "Monitorizar", tip: "Vulnerabilidades sin solución disponible o de bajo riesgo. Hay que vigilarlas pero no requieren acción inmediata." },
  { id: "conflicts", label: "Conflictos", tip: "Vulnerabilidades cuya solución puede romper otros paquetes. Requieren análisis antes de actualizar." },
];

// ─── Main ───
export default function App() {
  const [dark, setDark] = useState(false);
  const [tab, setTab] = useState("machines");
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState(null);
  const [selectedMachine, setSelectedMachine] = useState(null);

  const dn = dark ? "dark" : "light";

  const vulnsForMachine = (m) => VULNS.filter(v => v.machines.includes(m));
  const actionVulns = VULNS.filter(v => v.fixed && !v.hasConflict && !v.noFix);
  const monitorVulns = VULNS.filter(v => v.noFix || v.status === "monitoring");
  const conflictVulns = VULNS.filter(v => v.hasConflict);

  const currentList = useMemo(() => {
    let list;
    if (tab === "machines" && selectedMachine) list = vulnsForMachine(selectedMachine);
    else if (tab === "action") list = actionVulns;
    else if (tab === "monitor") list = monitorVulns;
    else if (tab === "conflicts") list = conflictVulns;
    else list = [];

    if (search) {
      const q = search.toLowerCase();
      list = list.filter(v =>
        v.id.toLowerCase().includes(q) || v.pkg.toLowerCase().includes(q) ||
        v.title.toLowerCase().includes(q) || v.what.toLowerCase().includes(q)
      );
    }

    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return list.sort((a, b) => order[a.severity] - order[b.severity]);
  }, [tab, selectedMachine, search]);

  const counts = { c: VULNS.filter(v => v.severity === "CRITICAL").length, h: VULNS.filter(v => v.severity === "HIGH").length, m: VULNS.filter(v => v.severity === "MEDIUM").length };

  return (
    <div className={`app ${dn}`}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,300;9..40,400;9..40,500;9..40,600;9..40,700&family=JetBrains+Mono:wght@400;500&display=swap');
        .app { --ff: 'DM Sans', system-ui, sans-serif; --mono: 'JetBrains Mono', monospace; --r: 16px; --rs: 10px; --t: 0.18s ease; min-height: 100vh; font-family: var(--ff); transition: background var(--t), color var(--t); }
        .app.light { --bg: #f8f9fc; --card: #fff; --card2: #f3f4f8; --brd: #e5e7ee; --brd2: #d1d5e0; --tx: #1a1c2e; --tx2: #5c5f78; --tx3: #9b9db3; --acc: #5558e6; --accbg: #5558e612; --shd: 0 1px 3px rgba(0,0,0,0.04), 0 4px 16px rgba(0,0,0,0.04); }
        .app.dark { --bg: #0c0d12; --card: #14161e; --card2: #1a1d28; --brd: #22253a; --brd2: #2e3350; --tx: #e6e8f0; --tx2: #8b8fa3; --tx3: #555770; --acc: #6c72ff; --accbg: #6c72ff15; --shd: 0 1px 3px rgba(0,0,0,0.2), 0 4px 16px rgba(0,0,0,0.3); }
        .app { background: var(--bg); color: var(--tx); } * { margin: 0; padding: 0; box-sizing: border-box; }
        .wrap { max-width: 1260px; margin: 0 auto; padding: 28px 20px; }

        /* Header */
        .hdr { display: flex; justify-content: space-between; align-items: center; margin-bottom: 28px; }
        .hdr h1 { font-size: 22px; font-weight: 700; letter-spacing: -0.4px; display: flex; align-items: center; gap: 10px; }
        .hdr h1 svg { color: var(--acc); }
        .hdr-sub { font-size: 12px; color: var(--tx3); margin-top: 3px; }
        .hdr-r { display: flex; gap: 8px; align-items: center; }
        .btn-icon { width: 36px; height: 36px; border-radius: 50%; background: var(--card); border: 1px solid var(--brd); display: flex; align-items: center; justify-content: center; cursor: pointer; color: var(--tx2); transition: all var(--t); }
        .btn-icon:hover { border-color: var(--acc); color: var(--acc); }
        .btn-primary { padding: 8px 16px; border-radius: var(--rs); background: var(--acc); color: white; border: none; font-family: var(--ff); font-size: 13px; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 6px; transition: all var(--t); }
        .btn-primary:hover { opacity: 0.88; }

        /* Summary bar */
        .summary { display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }
        .sum-card { flex: 1; min-width: 120px; background: var(--card); border: 1px solid var(--brd); border-radius: var(--r); padding: 16px 18px; display: flex; align-items: center; gap: 14px; transition: all var(--t); animation: fadeUp .3s ease both; }
        .sum-card:hover { border-color: var(--brd2); transform: translateY(-1px); }
        .sum-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
        .sum-val { font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }
        .sum-lbl { font-size: 11px; color: var(--tx3); text-transform: uppercase; letter-spacing: 0.4px; }
        @keyframes fadeUp { from { opacity:0; transform: translateY(10px); } to { opacity:1; transform: translateY(0); } }

        /* Tabs */
        .tabs { display: flex; gap: 3px; background: var(--card); border: 1px solid var(--brd); border-radius: var(--r); padding: 3px; margin-bottom: 18px; width: fit-content; }
        .tab { padding: 8px 16px; border-radius: 13px; border: none; background: transparent; color: var(--tx2); font-family: var(--ff); font-size: 13px; font-weight: 500; cursor: pointer; display: flex; align-items: center; gap: 6px; transition: all var(--t); white-space: nowrap; }
        .tab:hover { color: var(--tx); }
        .tab.on { background: var(--acc); color: white; }
        .tab-n { font-size: 10px; padding: 1px 6px; border-radius: 20px; background: rgba(255,255,255,0.2); font-weight: 700; }
        .tab:not(.on) .tab-n { background: var(--card2); color: var(--tx3); }

        /* Search */
        .search-row { display: flex; gap: 8px; margin-bottom: 14px; }
        .search { flex: 1; display: flex; align-items: center; gap: 8px; background: var(--card); border: 1px solid var(--brd); border-radius: var(--rs); padding: 0 12px; height: 38px; transition: border var(--t); }
        .search:focus-within { border-color: var(--acc); }
        .search svg { color: var(--tx3); flex-shrink: 0; }
        .search input { flex: 1; border: none; background: none; outline: none; font-family: var(--ff); font-size: 13px; color: var(--tx); }
        .search input::placeholder { color: var(--tx3); }

        /* Machine cards */
        .machines { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 12px; }
        .mcard { background: var(--card); border: 1px solid var(--brd); border-radius: var(--r); padding: 18px; cursor: pointer; transition: all var(--t); animation: fadeUp .3s ease both; position: relative; overflow: hidden; }
        .mcard:hover { border-color: var(--acc); transform: translateY(-2px); box-shadow: var(--shd); }
        .mcard-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 14px; }
        .mcard-name { font-size: 15px; font-weight: 700; }
        .mcard-role { font-size: 11px; color: var(--tx3); margin-top: 2px; }
        .mcard-icon { font-size: 20px; }
        .mcard-bar { display: flex; gap: 8px; flex-wrap: wrap; }
        .mcard-sev { display: flex; align-items: center; gap: 4px; font-size: 12px; font-weight: 600; padding: 3px 8px; border-radius: 6px; }
        .mcard-stripe { position: absolute; top: 0; left: 0; right: 0; height: 3px; border-radius: var(--r) var(--r) 0 0; }

        /* Back button */
        .back { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--tx2); cursor: pointer; margin-bottom: 14px; padding: 6px 0; border: none; background: none; font-family: var(--ff); transition: color var(--t); }
        .back:hover { color: var(--acc); }

        /* Vuln list */
        .vlist { display: flex; flex-direction: column; gap: 6px; }
        .vrow { background: var(--card); border: 1px solid var(--brd); border-radius: var(--r); overflow: hidden; transition: all var(--t); animation: fadeUp .25s ease both; }
        .vrow:hover { border-color: var(--brd2); }
        .vrow.open { border-color: var(--acc); }
        .vhdr { display: flex; justify-content: space-between; align-items: center; padding: 13px 16px; cursor: pointer; gap: 12px; }
        .vl { display: flex; align-items: center; gap: 10px; min-width: 0; flex: 1; }
        .sev-badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 9px; border-radius: 6px; font-size: 10px; font-weight: 700; letter-spacing: 0.3px; flex-shrink: 0; }
        .v-info { min-width: 0; }
        .v-id { font-family: var(--mono); font-size: 12px; font-weight: 500; }
        .v-title { font-size: 12px; color: var(--tx2); margin-top: 1px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 400px; }
        .vr { display: flex; align-items: center; gap: 8px; flex-shrink: 0; color: var(--tx3); }
        .v-pkg { display: flex; align-items: center; gap: 4px; font-size: 11px; color: var(--tx2); font-family: var(--mono); }
        .v-mtags { display: flex; gap: 3px; }
        .v-mtag { font-size: 9px; padding: 2px 7px; border-radius: 20px; font-weight: 600; color: white; }
        .conflict-pill { display: flex; align-items: center; gap: 3px; padding: 2px 8px; border-radius: 20px; font-size: 10px; font-weight: 600; }
        .nofix-pill { display: flex; align-items: center; gap: 3px; padding: 2px 8px; border-radius: 20px; font-size: 10px; font-weight: 600; background: var(--card2); color: var(--tx3); }

        /* Detail panel */
        .vdetail { border-top: 1px solid var(--brd); padding: 18px 16px; animation: fadeUp .2s ease both; }
        .detail-section { margin-bottom: 18px; }
        .detail-section:last-child { margin-bottom: 0; }
        .ds-title { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px; color: var(--tx3); margin-bottom: 8px; display: flex; align-items: center; gap: 6px; }
        .ds-body { font-size: 13px; line-height: 1.65; color: var(--tx2); }
        .ds-body strong { color: var(--tx); font-weight: 600; }

        .fix-box { padding: 14px; border-radius: var(--rs); margin-top: 6px; font-family: var(--mono); font-size: 12px; line-height: 1.6; white-space: pre-wrap; }
        .fix-box.safe { background: #0d966812; border: 1px solid #0d966830; color: #0d9668; }
        .app.dark .fix-box.safe { background: #34d39915; border-color: #34d39930; color: #34d399; }
        .fix-box.warn { background: #b4530912; border: 1px solid #b4530930; color: #b45309; }
        .app.dark .fix-box.warn { background: #ffb02015; border-color: #ffb02030; color: #ffb020; }
        .fix-box.nofix { background: var(--card2); border: 1px solid var(--brd); color: var(--tx3); }

        .conflict-card { background: var(--card2); border: 1px solid var(--brd); border-radius: var(--rs); padding: 14px; margin-top: 8px; }
        .cc-row { display: flex; gap: 10px; margin-bottom: 8px; align-items: flex-start; }
        .cc-row:last-child { margin-bottom: 0; }
        .cc-label { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px; min-width: 110px; flex-shrink: 0; }
        .cc-label.red { color: #dc2645; } .cc-label.orange { color: #e05520; } .cc-label.blue { color: #2d7dd2; } .cc-label.green { color: #0d9668; }
        .app.dark .cc-label.red { color: #ff3b5c; } .app.dark .cc-label.orange { color: #ff6b35; } .app.dark .cc-label.blue { color: #4d9fff; } .app.dark .cc-label.green { color: #34d399; }
        .cc-val { font-size: 12px; color: var(--tx2); line-height: 1.5; }

        .ver-row { display: flex; gap: 16px; margin-top: 6px; flex-wrap: wrap; }
        .ver-item { }
        .ver-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.3px; color: var(--tx3); }
        .ver-val { font-family: var(--mono); font-size: 13px; font-weight: 500; margin-top: 2px; }
        .ver-val.old { color: #dc2645; } .app.dark .ver-val.old { color: #ff3b5c; }
        .ver-val.new { color: #0d9668; } .app.dark .ver-val.new { color: #34d399; }
        .ver-val.none { color: var(--tx3); font-style: italic; }

        .img-list { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
        .img-tag { font-size: 11px; padding: 3px 8px; border-radius: 5px; background: var(--card2); font-family: var(--mono); color: var(--tx2); border: 1px solid var(--brd); }

        .dep-list { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
        .dep-tag { font-size: 11px; padding: 3px 8px; border-radius: 5px; background: var(--accbg); color: var(--acc); font-family: var(--mono); }

        .detail-link { display: inline-flex; align-items: center; gap: 4px; font-size: 12px; color: var(--acc); text-decoration: none; font-weight: 500; margin-top: 8px; }
        .detail-link:hover { opacity: 0.7; }

        /* Tooltip */
        .tip-wrap { position: relative; display: inline-flex; align-items: center; }
        .tip-bubble { position: absolute; z-index: 100; background: var(--tx); color: var(--bg); padding: 8px 12px; border-radius: 8px; font-size: 11px; line-height: 1.5; max-width: 280px; width: max-content; pointer-events: none; white-space: normal; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
        .info-dot { display: inline-flex; align-items: center; justify-content: center; width: 18px; height: 18px; border-radius: 50%; color: var(--tx3); cursor: help; transition: color var(--t); }
        .info-dot:hover { color: var(--acc); }

        .empty { text-align: center; padding: 60px 20px; color: var(--tx3); }
        .empty svg { margin-bottom: 10px; opacity: 0.3; }
        .empty p { font-size: 13px; }
        .count-txt { font-size: 11px; color: var(--tx3); margin-bottom: 10px; padding-left: 2px; }

        @media (max-width: 768px) {
          .machines { grid-template-columns: 1fr; }
          .vhdr { flex-direction: column; align-items: flex-start; }
          .vr { flex-wrap: wrap; }
          .v-title { max-width: 240px; }
          .summary { flex-direction: column; }
          .tabs { flex-wrap: wrap; }
        }
      `}</style>

      <div className="wrap">
        {/* Header */}
        <div className="hdr">
          <div>
            <h1><Icons.Shield size={22} /> Trivy Security</h1>
            <div className="hdr-sub">Último escaneo: 15 de marzo de 2026, 01:00 · {Object.keys(MACHINES).length} máquinas · {VULNS.length} vulnerabilidades</div>
          </div>
          <div className="hdr-r">
            <button className="btn-icon" onClick={() => setDark(!dark)}>{dark ? <Icons.Sun size={15} /> : <Icons.Moon size={15} />}</button>
            <button className="btn-primary"><Icons.Wrench size={13} /> Nuevo escaneo</button>
          </div>
        </div>

        {/* Summary */}
        <div className="summary">
          {[
            { v: counts.c, l: "Críticos", c: dark ? SEV.CRITICAL.darkColor : SEV.CRITICAL.color },
            { v: counts.h, l: "Altos", c: dark ? SEV.HIGH.darkColor : SEV.HIGH.color },
            { v: counts.m, l: "Medios", c: dark ? SEV.MEDIUM.darkColor : SEV.MEDIUM.color },
            { v: VULNS.length, l: "Total", c: dark ? "#6c72ff" : "#5558e6" },
          ].map((s, i) => (
            <div className="sum-card" key={i} style={{ animationDelay: `${i * 50}ms` }}>
              <div className="sum-dot" style={{ background: s.c }} />
              <div><div className="sum-val">{s.v}</div><div className="sum-lbl">{s.l}</div></div>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="tabs">
          {TABS.map(t => (
            <Tip key={t.id} text={t.tip}>
              <button className={`tab ${tab === t.id ? "on" : ""}`} onClick={() => { setTab(t.id); setSelectedMachine(null); setExpandedId(null); setSearch(""); }}>
                {t.label}
                <span className="tab-n">
                  {t.id === "machines" ? Object.keys(MACHINES).length : t.id === "action" ? actionVulns.length : t.id === "monitor" ? monitorVulns.length : conflictVulns.length}
                </span>
              </button>
            </Tip>
          ))}
        </div>

        {/* Machine view */}
        {tab === "machines" && !selectedMachine && (
          <div className="machines">
            {Object.entries(MACHINES).map(([name, m], i) => {
              const mv = vulnsForMachine(name);
              const mc = mv.filter(v => v.severity === "CRITICAL").length;
              const mh = mv.filter(v => v.severity === "HIGH").length;
              const mm = mv.filter(v => v.severity === "MEDIUM").length;
              return (
                <div className="mcard" key={name} style={{ animationDelay: `${i * 60}ms` }} onClick={() => setSelectedMachine(name)}>
                  <div className="mcard-stripe" style={{ background: m.color }} />
                  <div className="mcard-top">
                    <div><div className="mcard-name">{name}</div><div className="mcard-role">{m.role}{m.gpu ? " · GPU" : ""}</div></div>
                    <div className="mcard-icon">{m.icon}</div>
                  </div>
                  <div className="mcard-bar">
                    {mc > 0 && <div className="mcard-sev" style={{ background: dark ? SEV.CRITICAL.darkBg : SEV.CRITICAL.bg, color: dark ? SEV.CRITICAL.darkColor : SEV.CRITICAL.color }}>{mc} críticos</div>}
                    {mh > 0 && <div className="mcard-sev" style={{ background: dark ? SEV.HIGH.darkBg : SEV.HIGH.bg, color: dark ? SEV.HIGH.darkColor : SEV.HIGH.color }}>{mh} altos</div>}
                    {mm > 0 && <div className="mcard-sev" style={{ background: dark ? SEV.MEDIUM.darkBg : SEV.MEDIUM.bg, color: dark ? SEV.MEDIUM.darkColor : SEV.MEDIUM.color }}>{mm} medios</div>}
                    {mv.length === 0 && <div className="mcard-sev" style={{ background: "#0d966812", color: "#0d9668" }}>Limpia</div>}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Machine selected - back + search */}
        {tab === "machines" && selectedMachine && (
          <>
            <button className="back" onClick={() => { setSelectedMachine(null); setExpandedId(null); }}>
              <Icons.ArrowLeft size={15} /> Volver a máquinas
            </button>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
              <span style={{ fontSize: 20 }}>{MACHINES[selectedMachine]?.icon}</span>
              <div>
                <div style={{ fontWeight: 700, fontSize: 16 }}>{selectedMachine}</div>
                <div style={{ fontSize: 12, color: "var(--tx3)" }}>{MACHINES[selectedMachine]?.role} · {vulnsForMachine(selectedMachine).length} vulnerabilidades</div>
              </div>
            </div>
          </>
        )}

        {/* Search (for non-machines or machine selected) */}
        {(tab !== "machines" || selectedMachine) && (
          <div className="search-row">
            <div className="search">
              <Icons.Search size={14} />
              <input placeholder="Buscar por CVE, paquete o descripción..." value={search} onChange={e => setSearch(e.target.value)} />
              {search && <span style={{ cursor: "pointer", color: "var(--tx3)", display: "flex" }} onClick={() => setSearch("")}><Icons.X size={13} /></span>}
            </div>
          </div>
        )}

        {/* Results */}
        {(tab !== "machines" || selectedMachine) && (
          <>
            <div className="count-txt">{currentList.length} vulnerabilidad{currentList.length !== 1 ? "es" : ""}</div>
            <div className="vlist">
              {currentList.length === 0 ? (
                <div className="empty"><Icons.Check size={40} /><p>No se encontraron vulnerabilidades</p></div>
              ) : currentList.map((v, i) => {
                const s = SEV[v.severity];
                const isOpen = expandedId === v.id;
                return (
                  <div className={`vrow ${isOpen ? "open" : ""}`} key={v.id} style={{ animationDelay: `${i * 30}ms` }}>
                    <div className="vhdr" onClick={() => setExpandedId(isOpen ? null : v.id)}>
                      <div className="vl">
                        <div className="sev-badge" style={{ background: dark ? s.darkBg : s.bg, color: dark ? s.darkColor : s.color }}>
                          {v.severity === "CRITICAL" ? <Icons.Alert size={11} /> : v.severity === "HIGH" ? <Icons.Alert size={11} /> : <Icons.Info size={11} />}
                          {s.label}
                        </div>
                        <div className="v-info">
                          <div className="v-id">{v.id}</div>
                          <div className="v-title">{v.title}</div>
                        </div>
                      </div>
                      <div className="vr">
                        <div className="v-pkg"><Icons.Package size={12} /> {v.pkg}</div>
                        {v.hasConflict && <div className="conflict-pill" style={{ background: dark ? SEV.MEDIUM.darkBg : SEV.MEDIUM.bg, color: dark ? SEV.MEDIUM.darkColor : SEV.MEDIUM.color }}><Icons.Alert size={10} /> Conflicto</div>}
                        {v.noFix && <div className="nofix-pill">Sin solución</div>}
                        <div className="v-mtags">
                          {v.machines.map(m => <span key={m} className="v-mtag" style={{ background: MACHINES[m]?.color || "#666" }}>{m}</span>)}
                        </div>
                        {isOpen ? <Icons.ChevDown size={14} /> : <Icons.ChevRight size={14} />}
                      </div>
                    </div>

                    {isOpen && (
                      <div className="vdetail">
                        {/* Qué es */}
                        <div className="detail-section">
                          <div className="ds-title"><Icons.Info size={13} /> ¿Qué es esta vulnerabilidad? <InfoIcon text="Explicación en lenguaje sencillo de qué hace esta vulnerabilidad y cómo puede ser explotada." /></div>
                          <div className="ds-body">{v.what}</div>
                        </div>

                        {/* Por qué es grave */}
                        <div className="detail-section">
                          <div className="ds-title"><Icons.Alert size={13} /> ¿Por qué es {s.label.toLowerCase()}? <InfoIcon text={`Explicación de por qué esta vulnerabilidad tiene el nivel de severidad "${s.label}" y qué impacto real tiene en tu infraestructura.`} /></div>
                          <div className="ds-body">{v.why}</div>
                        </div>

                        {/* Versiones */}
                        <div className="detail-section">
                          <div className="ds-title"><Icons.Package size={13} /> Paquete afectado <InfoIcon text="El paquete (librería o programa) que tiene la vulnerabilidad, con la versión actual instalada y la versión que la corrige." /></div>
                          <div className="ver-row">
                            <div className="ver-item"><div className="ver-label">Paquete</div><div className="ver-val">{v.pkg}</div></div>
                            <div className="ver-item"><div className="ver-label">Tipo</div><div className="ver-val">{v.type}</div></div>
                            <div className="ver-item"><div className="ver-label">Versión actual</div><div className="ver-val old">{v.installed}</div></div>
                            <div className="ver-item"><div className="ver-label">Versión corregida</div><div className={`ver-val ${v.fixed ? "new" : "none"}`}>{v.fixed || "Sin solución aún"}</div></div>
                          </div>
                        </div>

                        {/* Dónde afecta */}
                        <div className="detail-section">
                          <div className="ds-title"><Icons.Server size={13} /> ¿Dónde afecta? <InfoIcon text="Las máquinas y las imágenes Docker que contienen este paquete vulnerable." /></div>
                          <div style={{ fontSize: 12, color: "var(--tx2)", marginBottom: 6 }}>
                            <strong>Máquinas:</strong> {v.machines.join(", ")}
                          </div>
                          <div className="img-list">
                            {v.images.map(img => <span key={img} className="img-tag">{img}</span>)}
                          </div>
                        </div>

                        {/* Paquetes que dependen de este */}
                        {v.dependsOn && v.dependsOn.length > 0 && (
                          <div className="detail-section">
                            <div className="ds-title"><Icons.Link size={13} /> Paquetes que dependen de este <InfoIcon text="Otros paquetes que usan este paquete internamente. Si actualizamos el paquete vulnerable, estos también pueden verse afectados." /></div>
                            <div className="dep-list">
                              {v.dependsOn.map(d => <span key={d} className="dep-tag">{d}</span>)}
                            </div>
                          </div>
                        )}

                        {/* Conflicto */}
                        {v.hasConflict && v.conflictDetail && (
                          <div className="detail-section">
                            <div className="ds-title"><Icons.Alert size={13} /> Conflicto de actualización <InfoIcon text="Si actualizamos este paquete a la versión corregida, otros paquetes pueden dejar de funcionar. Aquí se explica exactamente qué pasa y qué hacer." /></div>
                            <div className="conflict-card">
                              <div className="cc-row"><div className="cc-label red">Problema</div><div className="cc-val">{v.conflictDetail.problem}</div></div>
                              <div className="cc-row"><div className="cc-label orange">Situación actual</div><div className="cc-val">{v.conflictDetail.current}</div></div>
                              <div className="cc-row"><div className="cc-label blue">Qué pasa si actualizas</div><div className="cc-val">{v.conflictDetail.consequence}</div></div>
                              <div className="cc-row"><div className="cc-label green">Recomendación</div><div className="cc-val">{v.conflictDetail.recommendation}</div></div>
                            </div>
                          </div>
                        )}

                        {/* Qué hacer */}
                        <div className="detail-section">
                          <div className="ds-title"><Icons.Wrench size={13} /> ¿Qué hacer? <InfoIcon text="Los pasos exactos para arreglar esta vulnerabilidad. Si hay conflicto, se explica la alternativa." /></div>
                          <div className={`fix-box ${v.noFix ? "nofix" : v.hasConflict ? "warn" : "safe"}`}>
                            {v.howToFix}
                          </div>
                        </div>

                        {/* Link */}
                        <a className="detail-link" href={`https://nvd.nist.gov/vuln/detail/${v.id}`} target="_blank" rel="noopener noreferrer">
                          <Icons.External size={12} /> Más información sobre esta vulnerabilidad (Base de datos nacional de EEUU)
                        </a>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

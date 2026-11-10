# Signing spike — documento de traspaso

Todo lo necesario para continuar este trabajo en otra máquina (o para que otra sesión de Claude Code tenga el contexto).
Fecha del estado: 2026-11-10. Detalles técnicos finos en `README.md`; este documento es el "mapa".

## 1. Contexto: por qué existe esto

El frontend `accord_frontend` (Angular 21 + Ionic, un único proyecto con tres roles: Drone Operator, Infrastructure
Operator, Public Safety Operator) se quiere separar. Decisiones tomadas en la conversación:

| Tema | Decisión / recomendación acordada |
|---|---|
| Estructura | **Monorepo Angular CLI workspace** (migrable a Nx): 4 apps (`auth`, `drone-operator`, `infrastructure-operator`, `public-safety-operator`) + libs por capas (`core` → `ui` → `map` → `domain`, más `signing`) |
| Despliegue | Dos/tres URLs en el mismo servidor. **Recomendado: mismo origen con rutas** (`/login`, `/do`, `/io`, `/pso`) para compartir sesión sin código extra |
| Login | **Login único** en una app `auth`, con **selector de contexto (organización + rol)**, porque hay usuarios y organizaciones multirol. El backend emite el token con el contexto activo |
| Multirol hoy | **No está soportado**: `Organization.organizationType` es un único valor, `AuthService.getUserType()` lee un tipo, los guards expulsan y hacen `localStorage.clear()` si no coincide |
| Firma | **AutoFirma** (PAdES), mínimo **2 firmantes en secuencia** (p. ej. DO e IO), con botón "Firmar" cuando la coordinación está completa |
| Backend | **Java 8 + Spark** (`accord_backend`). **No se migra a Java 11**, por eso no se usa la librería DSS |
| Orden de trabajo | Fases 0–3 (análisis, limpieza, workspace, libs) no dependen de la firma. La firma es una fase posterior (7); este spike sirve para quitar incertidumbre antes |

Siguiente paso previsto del proyecto principal: **Fase 0** = informe de dependencias cruzadas DO↔IO↔PSO y reparto
fichero → app/lib (sin tocar código). Aún no se ha empezado.

## 2. Qué hay en este proyecto

```
signing-spike/
├── backend/      Spark API + verificador de firmas + sellado de tiempo (Java 8, Maven)
├── frontend/     Angular 21 mínimo + SigningService/AutoFirmaSigner (+ autoscript.js oficial en public/vendor)
├── certs/        scripts de certificados y de pruebas (ver §5)
├── run-backend.sh, sign-with-p12.sh
├── README.md     detalles técnicos
└── HANDOFF.md    este documento
```

### Qué demuestra (todo probado salvo lo indicado en §8)
1. Un PDF congelado lo firman 2 personas en secuencia con firmas **incrementales** PAdES.
2. El backend verifica cada subida: integridad, cobertura del archivo, cadena de confianza, **revocación (OCSP/CRL)**,
   **sello de tiempo**, que el nuevo PDF empiece con los bytes del anterior, y que solo se añada **una** firma.
3. Rechaza: PDF sin firma nueva, modificado/regenerado, firma manipulada, CA no confiable, versión obsoleta
   (dos personas a la vez), mismo certificado en dos roles, certificado revocado, sin sello, sello ajeno.
4. **Firma visible** en un recuadro por rol, definido por la plantilla del PDF.
5. El front solo habla con la interfaz `SigningService` (cambiar de proveedor no toca las apps).

### Flujo de una firma
```
[Firmar] → front descarga la versión vigente (X-Version) → AutoFirma firma (clave y PIN en el equipo del usuario)
 → front sube el PDF firmado (baseVersion) → backend: verificación pasada 1 → pide sello RFC 3161 a la TSA y lo incrusta
 → verificación pasada 2 de lo que se va a guardar → guarda versión n+1 → avisa al siguiente firmante
```

## 3. Requisitos de la máquina nueva

| Herramienta | Para qué | Nota |
|---|---|---|
| **JDK 8** | compilar y ejecutar el backend | Los scripts usan `/usr/lib/jvm/java-8-openjdk-amd64`; sobrescribible con `JAVA_HOME_8` |
| **Maven 3.8+** | build del backend | La primera vez descarga dependencias (necesita Internet) |
| **Node 20.19+** y npm | front | Angular 21. **No uses `ng` global** si no lo has instalado tú: en la máquina original `/usr/bin/ng` era otro programa. Usa `npx ng …` o `./node_modules/.bin/ng` |
| **openssl** | generar certificados de prueba y verificar CA | |
| **AutoFirma** (≥ 1.9) | firma real | https://firmaelectronica.gob.es/Home/Ciudadanos/Aplicaciones-Firma.html |
| `pdfsig`, `pdftoppm` (poppler-utils) | verificación independiente y render a PNG | opcional |
| `curl`, `python3`, `bash` | scripts | En Windows usar WSL o Git Bash |

Variable recomendada (igual que `accord_backend`): `JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF-8` (ya la ponen los scripts).

## 4. Puesta en marcha desde cero

```bash
git clone <repo> signing-spike && cd signing-spike

./certs/fetch-trust-roots.sh     # descarga y VERIFICA las CA públicas (FNMT y raíz de DigiCert) -> certs/trust, certs/trust-tsa
./certs/make-certs.sh            # CA de pruebas + 2 certificados de firmante (.p12, contraseña changeit) -> certs/trust-test, certs/out

./run-backend.sh                 # API en :8080 (compila con JDK 8 y arranca)
cd frontend && npm install && npx ng serve    # UI en http://localhost:4200
```

Los certificados y las CA **no están en git** (ver §9); estos dos scripts los regeneran.

## 5. Probar (de menos a más requisitos)

| Prueba | Comando | Necesita |
|---|---|---|
| Revocación con un respondedor OCSP local (bueno / revocado / caído, HARD y SOFT) | `./certs/ocsp-test.sh` | JDK 8 y openssl (compila el backend si hace falta) |
| **Flujo completo con AutoFirma real en línea de comandos** y certificados de prueba (2 firmas visibles + sello + verificación + PNG) | `./certs/autofirma-cli-test.sh` | AutoFirma instalada, `certs/out/*.p12`, Internet (TSA) |
| Firmar a mano sin AutoFirma | `./sign-with-p12.sh in.pdf out.pdf certs/out/signer-do.p12 "DO"` | solo JDK 8 |
| Verificar un PDF suelto | `java -cp "backend/target/classes:$(cat backend/target/cp.txt)" spike.VerifyCli f.pdf [trust] [trust-test] [HARD\|SOFT\|OFF] [REQUIRED\|OPTIONAL\|OFF] [trust-tsa]` | |
| Sellar un PDF suelto | `spike.StampCli in.pdf out.pdf http://timestamp.digicert.com [--wrong-imprint]` | Internet |
| **Navegador + AutoFirma** | abrir el front, "Create sample document", "Sign as DO" | AutoFirma con el certificado importado |
| Verificación externa | `pdfsig fichero.pdf` | poppler-utils |

Con los certificados de prueba, `pdfsig` dirá "Certificate issuer isn't Trusted": es normal (su CA no está en su lista).

### Certificado real (FNMT / DNIe)
1. `certs/fetch-trust-roots.sh` ya instala AC RAIZ FNMT-RCM y AC FNMT Usuarios. Para otra CA, copia su certificado
   (descargado de **su web oficial**) a `certs/trust/` y reinicia el backend (se leen solo al arrancar).
2. **Nunca** añadas a la confianza la cadena que viene dentro de un PDF firmado: sería fiarse de lo que el propio firmante dice.
3. Usa documentos de prueba: la firma identifica a una persona real. `backend/data/` guarda subject y huella; está ignorado por git.

### Importar los .p12 de prueba en AutoFirma
`certs/out/signer-do.p12` y `signer-io.p12` (contraseña `changeit`) deben estar en el almacén que lee AutoFirma
(Linux: normalmente el de Firefox/NSS; Windows/macOS: el del sistema). En Linux esto **no está verificado a fondo**: la
prueba en línea de comandos usa `-store pkcs12:` y no necesita importar nada.

## 6. Configuración del backend (variables de entorno)

| Variable | Por defecto | Significado |
|---|---|---|
| `PORT` | `8080` | |
| `ALLOWED_ORIGIN` | `http://localhost:4200` | CORS |
| `TRUST_DIR` | `../certs/trust` | CA reales: **siempre se comprueba su revocación** |
| `TEST_TRUST_DIR` | `../certs/trust-test` | CA de prueba: confiables pero **sin** comprobar revocación |
| `TSA_TRUST_DIR` | `../certs/trust-tsa` | raíces de TSA confiables |
| `REVOCATION` | `HARD` | `HARD` rechaza si no se puede saber; `SOFT` acepta avisando; `OFF` no comprueba |
| `TIMESTAMP` | `REQUIRED` | `REQUIRED` exige sello; `OPTIONAL` acepta sin; `OFF` ignora |
| `TSA_URL` | `http://timestamp.digicert.com` | TSA que usa el **servidor** |
| `DATA_DIR` | `data` | cada versión del PDF y `state.json` (solo para inspección) |

API: `POST /api/documents` · `GET /api/documents/:id` · `GET /api/documents/:id/pdf` (cabecera `X-Version`) ·
`POST /api/documents/:id/sign?baseVersion=n` (cuerpo = PDF firmado) · `GET /api/info`.
Códigos: 409 conflicto de versión, 422 firma rechazada (con detalle por firma), 503 la TSA no responde (no se guarda nada).

## 7. Lecciones aprendidas con AutoFirma (importante, cuestan horas)

1. **`alwaysCreateRevision=true` es obligatorio.** Por defecto, en la primera firma AutoFirma **reescribe todo el PDF**
   (solo añade al final si ya hay firmas). Sin esto la regla "el nuevo PDF empieza con los bytes del anterior" falla.
2. **No pongas `signatureSubFilter`.** Rompe el analizador de la línea de comandos combinado con otros parámetros; el valor
   por defecto (`ETSI.CAdES.detached`) es además el de PAdES baseline (el que espera eIDAS).
3. **No metas `\n` dentro de `layer2Text`**: rompe el analizador. El texto se ajusta solo al ancho del recuadro.
4. **Separador de parámetros:** la vía web (`autoscript.js`) usa saltos de línea reales; la **línea de comandos** espera el
   texto literal `\n` (barra invertida + n).
5. **AutoFirma 1.9.0 NO añade sello de tiempo a PAdES**: en `PdfTimestamper.buildCmsTimeStamper` busca el constructor con
   `tsaParamsClass.getClass()` (que es `java.lang.Class`), siempre falla con `NoSuchMethodException`, lo captura y firma **sin
   sello y sin error**. Sigue igual en su `master`. Por eso **sella el servidor** (`SignatureTimestamper`).
6. Firma visible: parámetros `signaturePage`, `signaturePositionOnPageLowerLeftX/Y`, `…UpperRightX/Y`, `layer2Text`
   (admite `$$SUBJECTCN$$`, `$$SIGNDATE=dd/MM/yyyy HH:mm:ss z$$`), `layer2FontFamily`, `layer2FontSize`. Coordenadas en puntos PDF,
   origen abajo-izquierda, página 1-based. Los nombres se verificaron contra `PdfExtraParams.java` del repo del Cliente @firma.
7. Filtro de certificado en la CLI: `-filter "subject.contains:texto"` (formato `tipo:valor`) o `-alias`.
8. La CLI traga errores del sellado: para depurar, llama a `es.gob.afirma.signers.pades.AOPDFSigner` desde `jshell` con
   `--class-path /usr/lib/Autofirma/autofirma.jar` y activa el logger `es.gob.afirma`.
9. Un script bash que arranca el servidor con `( … ) &` mata el subshell, no el `java`: usar `exec`. Y `pkill -f` puede
   matar tu propia línea de comandos si el patrón aparece en ella.

## 8. Qué NO está resuelto / no está probado

**Sin probar:** el flujo **desde el navegador con un certificado real** tras añadir el sello del servidor (la lógica es la misma
que en la prueba de línea de comandos, pero esa vía concreta no se ha ejecutado tras el último cambio); Windows/macOS;
otros navegadores; despliegue con HTTPS y en otro dominio (AutoFirma habla por un WebSocket local).

**Pendiente para producción:**
- **TSA cualificada eIDAS.** DigiCert NO lo es. ACCV (`http://tss.accv.es:8318/tsa`) e Izenpe (`http://tsa.izenpe.com`) responden
  RFC 3161; hay que añadir sus raíces a `certs/trust-tsa/` desde sus webs oficiales y decidir condiciones/coste.
- **Validez a largo plazo (PAdES-LT/LTA):** no se incrustan las respuestas OCSP/CRL ni certificados en el PDF; la revocación se
  consulta "ahora", en el momento de subir. DSS lo resolvería pero exige Java 11+ (descartado). Alternativa: microservicio aparte.
- **Cargar las CA desde las listas de confianza europeas (TSL/eIDAS)** en lugar de carpetas.
- **Vincular el NIF/CIF del certificado con el usuario/organización** (hoy solo "el mismo certificado no firma dos roles"; `TODO` en `Main.java`).
- Permisos reales (quién puede firmar qué en qué rol), almacenamiento en BD, notificaciones al siguiente firmante, rechazo/corrección
  tras la primera firma, caducidad del flujo, conmutación de contexto organización+rol.
- Los recuadros de firma son fijos (DO izquierda, IO derecha, página 1): las plantillas PDF reales deben reservarlos.
- La hora probada es la del **sello** (segundos después de firmar); la fecha `/M` del PDF solo la declara el firmante.
- Solo escritorio: AutoFirma no sirve en móvil/tablet (alternativa futura: firma remota con un proveedor cualificado).
- `autoscript.js` (en `frontend/public/vendor`) es del Cliente @firma, licencia GPL/EUPL: revisar antes de distribuir.

## 9. Subir a GitHub

Se puede. Recomendaciones:
- **Repositorio privado.** Aunque lo subido no contiene datos personales (se comprobó), es código de seguridad en evolución.
- Lo que **no** se sube (está en `.gitignore`): `certs/out/` (claves privadas de prueba), `certs/trust*/` (se regeneran con los
  scripts), `backend/data/` (**contiene PDFs firmados con tu certificado real**), `backend/target/`, `frontend/node_modules|dist|.angular`.
- No hay `gh` instalado en la máquina original; con `git` normal:
  ```bash
  cd signing-spike
  git add -A && git status        # revisa que no aparezcan .p12, .key, data/ ni PDFs
  git commit -m "Signing spike: AutoFirma multi-signer PAdES with OCSP and server-side timestamp"
  git remote add origin git@github.com:<usuario>/<repo>.git     # crea antes el repo PRIVADO en github.com
  git push -u origin main
  ```
- Antes del primer push, comprueba con `git ls-files | grep -E "\.(p12|key|pem)$|data/"` que no hay nada sensible.

## 10. Continuar con Claude Code en la otra máquina

La conversación no se transfiere; este documento es el contexto. Abre Claude Code en la carpeta del proyecto y di, por ejemplo:

> Lee HANDOFF.md y README.md. Estoy en una máquina nueva: ayúdame a poner en marcha el spike (sección 4) y a probar el flujo con AutoFirma.

Y para retomar el plan principal:

> Lee la sección 1 de HANDOFF.md. Empieza la Fase 0 del proyecto accord_frontend: informe de dependencias cruzadas entre
> pages/droneOperator, pages/infrastructureOperator y pages/publicSafetyOperator, y reparto fichero → app/lib. No cambies código.

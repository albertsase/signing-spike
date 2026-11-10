# Signing spike

> Para ponerlo en marcha en otra máquina y ver el estado completo (decisiones, lecciones, pendientes): **[HANDOFF.md](HANDOFF.md)**.

Throw-away project to validate **multi-signer PDF signing with AutoFirma** before touching the Accord refactor.
Not part of `accord_frontend`; nothing here is production code, but `SigningService` and the backend contract
are meant to be moved into the real project afterwards.

## What it proves

1. A frozen PDF can be signed by **2 people in sequence** (DO, then IO) with incremental PAdES signatures.
2. The backend (**Java 8 + Spark + PDFBox 2.0.30 + Bouncy Castle 1.76**, same versions as `accord_backend`) verifies
   every upload and rejects: no new signature, modified/regenerated PDF, tampered signature, untrusted CA,
   stale version (two people signing at once), same certificate signing for both roles.
3. The front only talks to a `SigningService` interface (`AutoFirmaSigner` today).

## Layout

```
backend/    Spark API + SignatureVerifier + DevSigner (dev tool that signs with a .p12)
frontend/   Angular 21 minimal UI (+ official AutoFirma JS client in public/vendor/autoscript.js)
certs/      make-certs.sh -> TEST CA + 2 test signer certificates (.p12, password: changeit)
            trust/       CAs trusted for real (always revocation-checked), e.g. FNMT
            trust-test/  test CAs: trusted but never revocation-checked (they have no OCSP/CRL)
            ocsp-test.sh local OCSP responder test: good / revoked / responder down (HARD, SOFT)
            trust-tsa/   roots of the time stamping authorities we trust (DigiCert Trusted Root G4)
            autofirma-cli-test.sh  real AutoFirma (command line) + test certs: 2 visible, timestamped signatures, verified by the backend
```

## Run

```bash
./certs/make-certs.sh          # once: creates certs/trust/*.pem (backend trusts it) and certs/out/*.p12
./run-backend.sh               # API on :8080, built and run with JDK 8
cd frontend && npx ng serve    # UI on :4200
```

## Test WITHOUT AutoFirma (works now)

Use the UI, or the API directly. In the UI, open "No AutoFirma? Test manually", download the PDF, then:

```bash
./sign-with-p12.sh downloaded.pdf signed.pdf certs/out/signer-do.p12 "DO"   # then upload signed.pdf
./sign-with-p12.sh signed.pdf signed2.pdf certs/out/signer-io.p12 "IO"      # second signer
```

Independent check: `pdfsig signed2.pdf` (poppler-utils).

## Test WITH AutoFirma (needs your action)

1. Install AutoFirma (https://firmaelectronica.gob.es/Home/Ciudadanos/Aplicaciones-Firma.html).
2. Import `certs/out/signer-do.p12` and `signer-io.p12` (password `changeit`) into the store AutoFirma reads
   (Linux: usually the Firefox/NSS store; Windows/macOS: system store). Check the AutoFirma docs for your OS.
3. In the UI press "Sign as DO", pick the certificate, then repeat for IO with the other certificate.
4. Repeat with a real certificate (FNMT / DNIe) and add its CA to `certs/trust/`.

## Visible signature

The PDF template decides where each role signs: `SamplePdf` draws an empty frame per role and exposes the same
rectangle (`box`: page, lower-left, upper-right, PDF points) in the document JSON. The front passes it to AutoFirma
(`signaturePage`, `signaturePositionOnPage*`, `layer2Text`...). Parameter names checked against `PdfExtraParams.java`.
Lessons learned with AutoFirma:
- `alwaysCreateRevision=true` is required (otherwise the first signature rewrites the whole PDF).
- Do NOT set `signatureSubFilter`; the default `ETSI.CAdES.detached` is the PAdES baseline one.
- Never put a `\n` inside `layer2Text` (breaks the parser); the text wraps inside the box by itself.
- The AutoFirma CLI wants parameters separated by the literal characters `\n`; the web client uses real newlines.

## Timestamp (PAdES-T), added by the SERVER

AutoFirma 1.9.0 cannot do it: in `PdfTimestamper.buildCmsTimeStamper` it looks up the constructor with
`tsaParamsClass.getClass()` (that is `java.lang.Class`) instead of `tsaParamsClass`, so it always fails with
`NoSuchMethodException`, the exception is swallowed and the PDF is signed WITHOUT timestamp and without any error
(still the same in the project's master). So the server does it (`SignatureTimestamper`):

1. verify the upload (pass 1, a missing timestamp is tolerated),
2. request an RFC 3161 token for hash(signature value) from `TSA_URL`, embed it in the CMS as an unsigned attribute
   (the /Contents field is outside the signed byte range, the file keeps the exact same length),
3. verify exactly what will be stored (pass 2): TSA signature + timeStamping EKU, imprint = THIS signature,
   TSA certificate chain to `certs/trust-tsa/` and not revoked, signer chain validated AT THE TIMESTAMP TIME.

If the TSA is down the upload is rejected with 503 and nothing is stored (`TIMESTAMP=OPTIONAL` accepts it unstamped).
Env: `TIMESTAMP=REQUIRED|OPTIONAL|OFF` (default REQUIRED), `TSA_URL` (default http://timestamp.digicert.com),
`TSA_TRUST_DIR`. DigiCert is NOT an eIDAS qualified TSA: for legal value use a qualified one (ACCV and Izenpe answer
RFC 3161 requests too; their roots must be added to `certs/trust-tsa/` from their official sites).
Dev tools: `spike.StampCli` (stamp a PDF, `--wrong-imprint` to test rejection), `spike.VerifyCli`.

## Known gaps (what a real implementation still needs)

- Revocation (OCSP, then CRL) **is checked** with the JDK PKIX validator (Java 8). Mode via env `REVOCATION=HARD|SOFT|OFF`
  (default HARD = reject when the status cannot be determined). The response is queried at upload time and not stored,
  so it is not long-term evidence (no PAdES-LT/LTA: OCSP/CRL responses and certificates are not embedded in the PDF).
  DSS was discarded on purpose (needs Java 11+).
- The timestamp is added by the server some seconds after the signature, so it proves existence at that time, not the exact
  moment of signing. The `/M` signing time inside the PDF is still only claimed by the signer.
- Certificate <-> user binding (NIF/CIF) is only a TODO in `Main.java`; here only "same cert cannot sign twice".
- Signature frames are fixed per role (DO left, IO right, page 1); the real templates must reserve them.
- Storage is in memory + files in `backend/data/` (no database, no auth, no permissions).
- AutoFirma PAdES `extraParams` names must be checked against the installed version.
- `autoscript.js` is from the Cliente @firma project (GPL/EUPL licensed): review the licence before shipping.

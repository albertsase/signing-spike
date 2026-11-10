package spike;

import static spark.Spark.before;
import static spark.Spark.exception;
import static spark.Spark.get;
import static spark.Spark.options;
import static spark.Spark.port;
import static spark.Spark.post;

import java.io.File;
import java.nio.file.Files;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import com.google.gson.Gson;

import spark.Response;

/**
 * Signing spike API (Spark, Java 8 - same stack as accord_backend).
 *
 *   POST /api/documents                        create a sample document with 2 required signers (DO, IO)
 *   GET  /api/documents/:id                    workflow state
 *   GET  /api/documents/:id/pdf                current version of the PDF (always sign THIS one)
 *   POST /api/documents/:id/sign?baseVersion=n body = signed PDF (application/pdf); verified before being accepted
 *   GET  /api/info                             trust anchors loaded, etc.
 */
public class Main {

    private static final Gson GSON = new Gson();
    private static final Map<String, SigningDocument> DOCS = new ConcurrentHashMap<String, SigningDocument>();

    public static void main(String[] args) throws Exception {
        final int portNumber = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        final File trustDir = new File(System.getenv().getOrDefault("TRUST_DIR", "../certs/trust"));
        final File testTrustDir = new File(System.getenv().getOrDefault("TEST_TRUST_DIR", "../certs/trust-test"));
        final SignatureVerifier.RevocationMode revocation =
                SignatureVerifier.RevocationMode.valueOf(System.getenv().getOrDefault("REVOCATION", "HARD").toUpperCase());
        final File tsaTrustDir = new File(System.getenv().getOrDefault("TSA_TRUST_DIR", "../certs/trust-tsa"));
        final SignatureVerifier.TimestampMode timestamp =
                SignatureVerifier.TimestampMode.valueOf(System.getenv().getOrDefault("TIMESTAMP", "REQUIRED").toUpperCase());
        final String tsaUrl = System.getenv().getOrDefault("TSA_URL", "http://timestamp.digicert.com");
        final SignatureTimestamper timestamper = new SignatureTimestamper(tsaUrl, 15000);
        final File dataDir = new File(System.getenv().getOrDefault("DATA_DIR", "data"));
        final String allowedOrigin = System.getenv().getOrDefault("ALLOWED_ORIGIN", "http://localhost:4200");
        dataDir.mkdirs();

        final SignatureVerifier verifier = new SignatureVerifier(trustDir, testTrustDir, tsaTrustDir, revocation, timestamp);
        System.out.println("Trusted CAs loaded from " + trustDir.getAbsolutePath() + ": " + verifier.trustAnchorCount()
                + " (test CAs from " + testTrustDir.getAbsolutePath() + "), TSA roots: " + verifier.tsaAnchorCount()
                + ", revocation mode: " + revocation + ", timestamp mode: " + timestamp + ", TSA: " + tsaUrl);

        port(portNumber);

        before((req, res) -> {
            res.header("Access-Control-Allow-Origin", allowedOrigin);
            res.header("Access-Control-Allow-Headers", "Content-Type");
            res.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
            res.header("Access-Control-Expose-Headers", "X-Version");
        });
        options("/*", (req, res) -> "");

        get("/api/info", (req, res) -> {
            Map<String, Object> m = new LinkedHashMap<String, Object>();
            m.put("trustedCas", verifier.trustAnchorCount());
            m.put("java", System.getProperty("java.version"));
            m.put("revocationMode", verifier.revocationMode().toString());
            m.put("timestampMode", verifier.timestampMode().toString());
            m.put("tsaUrl", tsaUrl);
            return json(res, m);
        });

        post("/api/documents", (req, res) -> {
            SigningDocument d = new SigningDocument();
            d.id = UUID.randomUUID().toString();
            d.title = "Coordination agreement " + d.id.substring(0, 8);
            d.status = "IN_PROGRESS";
            d.version = 0;
            d.signers.add(pending("DO"));
            d.signers.add(pending("IO"));
            d.versions.add(SamplePdf.create(d.title));
            DOCS.put(d.id, d);
            persist(dataDir, d);
            return json(res, d);
        });

        get("/api/documents/:id", (req, res) -> {
            SigningDocument d = DOCS.get(req.params("id"));
            if (d == null) {
                return error(res, 404, "Unknown document");
            }
            return json(res, d);
        });

        get("/api/documents/:id/pdf", (req, res) -> {
            SigningDocument d = DOCS.get(req.params("id"));
            if (d == null) {
                return error(res, 404, "Unknown document");
            }
            res.type("application/pdf");
            res.header("X-Version", String.valueOf(d.version));
            res.raw().getOutputStream().write(d.currentPdf());
            res.raw().getOutputStream().flush();
            return res.raw();
        });

        post("/api/documents/:id/sign", (req, res) -> {
            final SigningDocument d = DOCS.get(req.params("id"));
            if (d == null) {
                return error(res, 404, "Unknown document");
            }
            synchronized (d) {
                String base = req.queryParams("baseVersion");
                if (base == null || Integer.parseInt(base) != d.version) {
                    return error(res, 409, "Version conflict: the document is at version " + d.version
                            + ", you signed version " + base + ". Download the current version and sign again.");
                }
                SigningDocument.Signer next = d.nextPending();
                if (next == null) {
                    return error(res, 409, "The document is already fully signed.");
                }
                byte[] uploaded = req.bodyAsBytes();
                // Pass 1: everything except the timestamp, which the server adds right after (AutoFirma cannot do it).
                SignatureVerifier.Result r = verifier.verify(d.currentPdf(), uploaded, true);
                if (!r.ok) {
                    return rejected(res, r);
                }
                // Add the RFC 3161 timestamp to the new signature, unless it already carries one.
                SignatureVerifier.SigInfo fresh = r.signatures.get(r.signatures.size() - 1);
                if (verifier.timestampMode() != SignatureVerifier.TimestampMode.OFF && "NONE".equals(fresh.timestamp)) {
                    try {
                        uploaded = timestamper.addTimestamp(uploaded);
                    } catch (SignatureTimestamper.TimestampException e) {
                        if (verifier.timestampMode() == SignatureVerifier.TimestampMode.REQUIRED) {
                            return error(res, 503, "Could not timestamp the signature, nothing was saved. Try again. (" + e.getMessage() + ")");
                        }
                    }
                }
                // Pass 2: full verification of exactly what will be stored (timestamp, chain at the TSA time, revocation...).
                r = verifier.verify(d.currentPdf(), uploaded);
                if (!r.ok) {
                    return rejected(res, r);
                }
                SignatureVerifier.SigInfo added = r.signatures.get(r.signatures.size() - 1);

                // Business rule demo: the same certificate cannot sign for two roles (separation of duties).
                for (SigningDocument.Signer s : d.signers) {
                    if (added.fingerprintSha256.equals(s.fingerprintSha256)) {
                        return error(res, 422, "This certificate already signed for role " + s.role + ".");
                    }
                }
                // TODO real system: compare certificate NIF/CIF with the NIF/CIF of the user/organization for this role.

                next.status = "SIGNED";
                next.subject = added.subject;
                next.fingerprintSha256 = added.fingerprintSha256;
                next.signedAt = new Date().toString();
                d.versions.add(uploaded);
                d.version = d.versions.size() - 1;
                if (d.nextPending() == null) {
                    d.status = "COMPLETED";
                }
                persist(dataDir, d);

                Map<String, Object> m = new LinkedHashMap<String, Object>();
                m.put("document", d);
                m.put("signatures", r.signatures);
                return json(res, m);
            }
        });

        exception(Exception.class, (e, req, res) -> {
            e.printStackTrace();
            res.status(500);
            res.type("application/json");
            res.body(GSON.toJson(java.util.Collections.singletonMap("error", String.valueOf(e))));
        });

        System.out.println("Signing spike API on http://localhost:" + portNumber + " (CORS: " + allowedOrigin + ")");
    }

    private static String rejected(Response res, SignatureVerifier.Result r) {
        res.status(422);
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        m.put("error", r.error);
        m.put("signatures", r.signatures);
        return json(res, m);
    }

    private static SigningDocument.Signer pending(String role) {
        SigningDocument.Signer s = new SigningDocument.Signer();
        s.role = role;
        s.status = "PENDING";
        s.box = SamplePdf.boxFor(role);
        return s;
    }

    private static String json(Response res, Object o) {
        res.type("application/json");
        return GSON.toJson(o);
    }

    private static String error(Response res, int status, String msg) {
        res.status(status);
        return json(res, java.util.Collections.singletonMap("error", msg));
    }

    /** Writes every version to disk so they can be opened with Adobe / inspected with pdfsig. */
    private static void persist(File dataDir, SigningDocument d) throws Exception {
        File dir = new File(dataDir, d.id);
        dir.mkdirs();
        for (int i = 0; i < d.versions.size(); i++) {
            Files.write(new File(dir, "v" + i + ".pdf").toPath(), d.versions.get(i));
        }
        Files.write(new File(dir, "state.json").toPath(), GSON.toJson(d).getBytes("UTF-8"));
    }
}

package spike;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

/**
 * Verifies the PAdES / PKCS#7 detached signatures of a PDF with PDFBox 2.0 + Bouncy Castle + the JDK PKIX validator
 * (Java 8 compatible, no DSS).
 *
 * What it checks:
 *  - cryptographic integrity of every signature (the hash covers the bytes declared in /ByteRange)
 *  - the last signature covers the whole file (nothing appended after it)
 *  - the certificate chain ends in one of our trusted CAs
 *  - SIGNATURE TIMESTAMP (RFC 3161 token in the CMS unsigned attributes, PAdES-T): the token is signed by a TSA that
 *    chains to a trusted TSA root, it was issued for THIS signature (message imprint) and the TSA certificate is not revoked.
 *    When a valid timestamp exists, the signer certificate chain is validated AT THE TIMESTAMP TIME (proven), otherwise at
 *    the time claimed by the signer (not proven).
 *  - REVOCATION (OCSP, then CRL) of the signer certificate, intermediate CAs and TSA certificate, queried NOW
 *  - incremental rule: the new file starts with the exact bytes of the previous version and adds exactly one signature
 *
 * What it does NOT do yet:
 *  - keep the OCSP/CRL responses as evidence inside the PDF (PAdES-LT/LTA): needed for validity many years later
 *  - load the CA / TSA lists from the EU trusted lists (TSL); they are loaded from folders
 */
public class SignatureVerifier {

    /** HARD: reject when revocation status cannot be determined. SOFT: accept it (but report it). OFF: do not check. */
    public enum RevocationMode { HARD, SOFT, OFF }

    /** REQUIRED: reject signatures without a valid timestamp. OPTIONAL: accept without, but a present one must be valid. OFF: ignore. */
    public enum TimestampMode { REQUIRED, OPTIONAL, OFF }

    public static class SigInfo {
        public int index;
        public String subject;
        public String issuer;
        public String serialHex;
        public String fingerprintSha256;
        public String signDate;        // claimed by the signer
        public String notBefore;
        public String notAfter;
        public boolean integrityOk;
        public boolean chainOk;
        public boolean revocationOk;
        public String revocation;      // GOOD | REVOKED | UNKNOWN: reason | SKIPPED: reason
        public boolean timestampOk;
        public String timestamp;       // NONE | OK | INVALID: reason | SKIPPED
        public String timestampTime;   // proven time (TSA genTime)
        public String timestampTsa;    // TSA certificate subject
        public boolean coversWholeFile;
        public String error;
    }

    public static class Result {
        public boolean ok;
        public String error;
        public List<SigInfo> signatures = new ArrayList<SigInfo>();
    }

    private static class ChainCheck {
        boolean chainOk;
        boolean revocationOk;
        String revocation;
        String error;
    }

    private static class TsCheck {
        boolean ok;
        String status;
        Date time;
        String tsa;
        String error;
    }

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        // Make the JDK validator use the OCSP responder / CRL distribution points found in the certificates.
        Security.setProperty("ocsp.enable", "true");
        System.setProperty("com.sun.security.enableCRLDP", "true");
        System.setProperty("com.sun.security.ocsp.timeout", "10");
    }

    private final Set<TrustAnchor> anchors = new HashSet<TrustAnchor>();
    private final Set<X509Certificate> testCas = new HashSet<X509Certificate>();
    private final Set<TrustAnchor> tsaAnchors = new HashSet<TrustAnchor>();
    private final RevocationMode mode;
    private final TimestampMode tsMode;

    /**
     * @param trustDir     CAs we trust for real (their certificates are always revocation-checked)
     * @param testTrustDir CAs used only for tests (no OCSP/CRL available): trusted but never revocation-checked. May be null.
     * @param tsaTrustDir  roots of the time stamping authorities we trust. May be null.
     */
    public SignatureVerifier(File trustDir, File testTrustDir, File tsaTrustDir, RevocationMode mode, TimestampMode tsMode)
            throws Exception {
        this.mode = mode;
        this.tsMode = tsMode;
        for (X509Certificate c : load(trustDir)) {
            anchors.add(new TrustAnchor(c, null));
        }
        for (X509Certificate c : load(testTrustDir)) {
            anchors.add(new TrustAnchor(c, null));
            testCas.add(c);
        }
        for (X509Certificate c : load(tsaTrustDir)) {
            tsaAnchors.add(new TrustAnchor(c, null));
        }
    }

    private static List<X509Certificate> load(File dir) throws Exception {
        List<X509Certificate> out = new ArrayList<X509Certificate>();
        if (dir == null) {
            return out;
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        File[] files = dir.listFiles();
        if (files == null) {
            return out;
        }
        for (File f : files) {
            String n = f.getName().toLowerCase();
            if (!(n.endsWith(".pem") || n.endsWith(".crt") || n.endsWith(".cer"))) {
                continue;
            }
            InputStream in = new FileInputStream(f);
            try {
                for (Certificate c : cf.generateCertificates(in)) {
                    out.add((X509Certificate) c);
                }
            } finally {
                in.close();
            }
        }
        return out;
    }

    public int trustAnchorCount() {
        return anchors.size();
    }

    public int tsaAnchorCount() {
        return tsaAnchors.size();
    }

    public RevocationMode revocationMode() {
        return mode;
    }

    public TimestampMode timestampMode() {
        return tsMode;
    }

    public int countSignatures(byte[] pdf) throws IOException {
        PDDocument doc = PDDocument.load(pdf);
        try {
            return doc.getSignatureDictionaries().size();
        } finally {
            doc.close();
        }
    }

    /**
     * @param previous bytes of the version the signer started from (null for a standalone check)
     * @param current  bytes uploaded by the client
     */
    public Result verify(byte[] previous, byte[] current) {
        return verify(previous, current, false);
    }

    /**
     * @param timestampMayBeMissing true for the FIRST pass of the upload flow: the new signature may still lack its
     *        timestamp because the server adds it right after (a timestamp that is present must always be valid).
     */
    public Result verify(byte[] previous, byte[] current, boolean timestampMayBeMissing) {
        Result r = new Result();
        try {
            int previousCount = 0;
            if (previous != null) {
                if (current.length <= previous.length) {
                    return fail(r, "The uploaded file is not longer than the previous version (no signature was added).");
                }
                if (!Arrays.equals(previous, Arrays.copyOf(current, previous.length))) {
                    return fail(r, "The uploaded file does not start with the previous version: the document was modified or regenerated.");
                }
                previousCount = countSignatures(previous);
            }

            PDDocument doc = PDDocument.load(current);
            try {
                List<PDSignature> sigs = doc.getSignatureDictionaries();
                if (sigs.isEmpty()) {
                    return fail(r, "The PDF has no signatures.");
                }
                boolean allOk = true;
                for (int i = 0; i < sigs.size(); i++) {
                    SigInfo info = verifyOne(i, sigs.get(i), current, i == sigs.size() - 1, timestampMayBeMissing && i == sigs.size() - 1);
                    r.signatures.add(info);
                    if (!(info.integrityOk && info.chainOk && info.revocationOk && info.timestampOk && info.coversWholeFile)) {
                        allOk = false;
                    }
                }
                if (!allOk) {
                    return fail(r, "At least one signature is not valid (see details).");
                }
                if (previous != null && sigs.size() != previousCount + 1) {
                    return fail(r, "Expected exactly one new signature (previous: " + previousCount + ", now: " + sigs.size() + ").");
                }
            } finally {
                doc.close();
            }
            r.ok = true;
            return r;
        } catch (Exception e) {
            return fail(r, "Verification error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private Result fail(Result r, String msg) {
        r.ok = false;
        r.error = msg;
        return r;
    }

    private SigInfo verifyOne(int index, PDSignature sig, byte[] file, boolean isLast, boolean tsMayBeMissing) {
        SigInfo info = new SigInfo();
        info.index = index;
        try {
            int[] br = sig.getByteRange();
            long end = (long) br[2] + (long) br[3];
            info.coversWholeFile = isLast ? end == file.length : end < file.length;

            byte[] signed = sig.getSignedContent(file);
            byte[] contents = sig.getContents(file);
            CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(signed), contents);
            SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();

            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> matches = cms.getCertificates().getMatches(signer.getSID());
            if (matches.isEmpty()) {
                info.error = "Signer certificate not embedded in the signature.";
                return info;
            }
            JcaX509CertificateConverter conv = new JcaX509CertificateConverter().setProvider("BC");
            X509Certificate cert = conv.getCertificate(matches.iterator().next());

            info.subject = cert.getSubjectX500Principal().getName();
            info.issuer = cert.getIssuerX500Principal().getName();
            info.serialHex = cert.getSerialNumber().toString(16);
            info.fingerprintSha256 = hex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
            info.notBefore = cert.getNotBefore().toString();
            info.notAfter = cert.getNotAfter().toString();
            Calendar sd = sig.getSignDate();
            info.signDate = sd == null ? null : sd.getTime().toString();

            info.integrityOk = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));

            // Timestamp first: if valid, it gives the PROVEN time at which the certificate chain must be valid.
            TsCheck ts = checkTimestamp(signer, conv, tsMayBeMissing);
            info.timestampOk = ts.ok;
            info.timestamp = ts.status;
            info.timestampTsa = ts.tsa;
            info.timestampTime = ts.time == null ? null : ts.time.toString();

            List<Certificate> embedded = new ArrayList<Certificate>();
            for (Object o : cms.getCertificates().getMatches(null)) {
                embedded.add(conv.getCertificate((X509CertificateHolder) o));
            }
            Date validationTime = ts.time != null ? ts.time : (sd == null ? new Date() : sd.getTime());
            Set<TrustAnchor> all = new HashSet<TrustAnchor>(anchors);
            ChainCheck cc = checkChain(cert, embedded, validationTime, all, testCas);
            info.chainOk = cc.chainOk;
            info.revocationOk = cc.revocationOk;
            info.revocation = cc.revocation;
            if (cc.error != null) {
                info.error = cc.error;
            }
            if (ts.error != null) {
                info.error = info.error == null ? ts.error : info.error + " " + ts.error;
            }
        } catch (Exception e) {
            info.error = e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        return info;
    }

    /** Verifies the RFC 3161 signature timestamp token carried in the CMS unsigned attributes (PAdES-T). */
    private TsCheck checkTimestamp(SignerInformation signer, JcaX509CertificateConverter conv, boolean mayBeMissing) {
        TsCheck t = new TsCheck();
        if (tsMode == TimestampMode.OFF) {
            t.ok = true;
            t.status = "SKIPPED: timestamp check disabled";
            return t;
        }
        AttributeTable unsigned = signer.getUnsignedAttributes();
        Attribute attr = unsigned == null ? null : unsigned.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        if (attr == null) {
            t.status = "NONE";
            t.ok = tsMode != TimestampMode.REQUIRED || mayBeMissing;
            if (!t.ok) {
                t.error = "The signature has no timestamp (PAdES-T required): its signing time is only claimed by the signer.";
            }
            return t;
        }
        try {
            ASN1Encodable value = attr.getAttrValues().getObjectAt(0);
            TimeStampToken token = new TimeStampToken(new CMSSignedData(ContentInfo.getInstance(value)));

            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> tsaMatches = token.getCertificates().getMatches(token.getSID());
            if (tsaMatches.isEmpty()) {
                return invalid(t, "the token does not embed the TSA certificate (tsaRequireCert=true is needed)");
            }
            X509Certificate tsaCert = conv.getCertificate(tsaMatches.iterator().next());
            t.tsa = tsaCert.getSubjectX500Principal().getName();

            // 1) the token is signed by that TSA certificate, which has the timeStamping extended key usage
            token.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(tsaCert));

            // 2) the token was issued for THIS signature: imprint = hash(signature value)
            TimeStampTokenInfo info = token.getTimeStampInfo();
            DigestCalculator dc = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(info.getHashAlgorithm());
            dc.getOutputStream().write(signer.getSignature());
            dc.getOutputStream().close();
            if (!Arrays.equals(dc.getDigest(), info.getMessageImprintDigest())) {
                return invalid(t, "the timestamp does not belong to this signature (message imprint mismatch)");
            }

            // 3) the TSA certificate chains to a trusted TSA root at the time of the token, and is not revoked
            List<Certificate> tsaEmbedded = new ArrayList<Certificate>();
            for (Object o : token.getCertificates().getMatches(null)) {
                tsaEmbedded.add(conv.getCertificate((X509CertificateHolder) o));
            }
            Date gen = info.getGenTime();
            ChainCheck cc = checkChain(tsaCert, tsaEmbedded, gen, tsaAnchors, Collections.<X509Certificate>emptySet());
            if (!cc.chainOk) {
                return invalid(t, "TSA certificate not trusted: " + cc.error);
            }
            if (!cc.revocationOk) {
                return invalid(t, "TSA certificate revocation: " + cc.revocation);
            }

            t.ok = true;
            t.time = gen;
            t.status = "OK";
            return t;
        } catch (Exception e) {
            return invalid(t, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private TsCheck invalid(TsCheck t, String why) {
        t.ok = false;
        t.status = "INVALID: " + why;
        t.error = "Invalid timestamp: " + why + ".";
        return t;
    }

    /**
     * Two phases: (1) build the path to a trusted CA, valid at {@code at}; (2) check revocation of that path with
     * OCSP/CRL. Revocation is queried NOW, which is correct when verifying at upload time (right after signing);
     * re-validating old signatures years later needs stored evidence (PAdES-LT), not implemented here.
     *
     * @param exempt anchors (test CAs) that are trusted but never revocation-checked
     */
    private ChainCheck checkChain(X509Certificate cert, List<Certificate> embedded, Date at,
            Set<TrustAnchor> trust, Set<X509Certificate> exempt) {
        ChainCheck r = new ChainCheck();
        Set<TrustAnchor> all = new HashSet<TrustAnchor>(trust);
        for (X509Certificate c : exempt) {
            all.add(new TrustAnchor(c, null));
        }
        if (all.isEmpty()) {
            r.error = "No trusted CAs configured.";
            r.revocation = "SKIPPED: no chain";
            return r;
        }

        CertPath path;
        TrustAnchor anchor;
        try {
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(cert);
            PKIXBuilderParameters p = new PKIXBuilderParameters(all, target);
            p.setRevocationEnabled(false);
            p.setDate(at);
            p.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(embedded)));
            PKIXCertPathBuilderResult res = (PKIXCertPathBuilderResult) CertPathBuilder.getInstance("PKIX").build(p);
            path = res.getCertPath();
            anchor = res.getTrustAnchor();
        } catch (Exception e) {
            r.error = "Certificate chain is not trusted (untrusted CA, expired at " + at + " or broken chain): " + e.getMessage();
            r.revocation = "SKIPPED: no chain";
            return r;
        }
        r.chainOk = true;

        if (mode == RevocationMode.OFF) {
            r.revocationOk = true;
            r.revocation = "SKIPPED: revocation check disabled";
            return r;
        }
        if (exempt.contains(anchor.getTrustedCert())) {
            r.revocationOk = true;
            r.revocation = "SKIPPED: test CA (no OCSP/CRL)";
            return r;
        }

        try {
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            PKIXRevocationChecker rc = (PKIXRevocationChecker) validator.getRevocationChecker();
            rc.setOptions(mode == RevocationMode.SOFT
                    ? EnumSet.of(PKIXRevocationChecker.Option.SOFT_FAIL)
                    : EnumSet.noneOf(PKIXRevocationChecker.Option.class));
            PKIXParameters vp = new PKIXParameters(Collections.singleton(anchor));
            vp.setRevocationEnabled(false); // the checker added below does it
            vp.addCertPathChecker(rc);
            validator.validate(path, vp);

            if (rc.getSoftFailExceptions().isEmpty()) {
                r.revocation = "GOOD";
            } else {
                r.revocation = "UNKNOWN (accepted, soft-fail): " + rc.getSoftFailExceptions().get(0).getMessage();
            }
            r.revocationOk = true;
        } catch (CertPathValidatorException e) {
            r.revocationOk = false;
            if (e.getReason() == CertPathValidatorException.BasicReason.REVOKED) {
                r.revocation = "REVOKED";
                r.error = "The certificate (or a CA in its chain) is REVOKED.";
            } else {
                r.revocation = "UNKNOWN: " + e.getMessage();
                r.error = "Revocation status could not be determined (" + e.getMessage() + ").";
            }
        } catch (Exception e) {
            r.revocationOk = false;
            r.revocation = "UNKNOWN: " + e;
            r.error = "Revocation check failed: " + e;
        }
        return r;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }
}

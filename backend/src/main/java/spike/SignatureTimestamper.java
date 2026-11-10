package spike;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * Adds an RFC 3161 SIGNATURE TIMESTAMP (PAdES-T) to the LAST signature of a PDF, on the server.
 *
 * Why on the server: AutoFirma 1.9.0 silently drops the timestamp in PAdES (bug in PdfTimestamper.buildCmsTimeStamper),
 * and doing it here also lets the server own the TSA policy.
 *
 * How it stays valid: the timestamp is an UNSIGNED attribute of the CMS stored in the /Contents hex string. /Contents is
 * excluded from the signed /ByteRange, so replacing it does not alter anything the signature covers; the file keeps
 * exactly the same length (zero padded), so later incremental signatures and the "previous bytes" rule keep working.
 */
public class SignatureTimestamper {

    public static class TimestampException extends Exception {
        public TimestampException(String message, Throwable cause) {
            super(message, cause);
        }

        public TimestampException(String message) {
            super(message);
        }
    }

    private final String tsaUrl;
    private final int timeoutMs;

    public SignatureTimestamper(String tsaUrl, int timeoutMs) {
        this.tsaUrl = tsaUrl;
        this.timeoutMs = timeoutMs;
    }

    public byte[] addTimestamp(byte[] pdf) throws TimestampException {
        return addTimestamp(pdf, null);
    }

    /** @param imprintOverride DEV/TEST ONLY: hash to request instead of hash(signature value), to test the verifier. */
    byte[] addTimestamp(byte[] pdf, byte[] imprintOverride) throws TimestampException {
        try {
            PDDocument doc = PDDocument.load(pdf);
            PDSignature sig;
            try {
                List<PDSignature> sigs = doc.getSignatureDictionaries();
                if (sigs.isEmpty()) {
                    throw new TimestampException("The PDF has no signatures.");
                }
                sig = sigs.get(sigs.size() - 1);
            } finally {
                doc.close();
            }

            // The /Contents hex string lives in the gap of the byte range: <hex...>
            int[] br = sig.getByteRange();
            int gapStart = br[1];
            int gapEnd = br[2];
            if (pdf[gapStart] != '<' || pdf[gapEnd - 1] != '>') {
                throw new TimestampException("Unexpected /Contents layout.");
            }
            int capacityHexChars = gapEnd - gapStart - 2;

            CMSSignedData cms = new CMSSignedData(sig.getContents(pdf));
            SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();

            byte[] imprint = imprintOverride != null
                    ? imprintOverride
                    : MessageDigest.getInstance("SHA-256").digest(signer.getSignature());
            TimeStampToken token = requestToken(imprint);

            Attribute tsAttr = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                    new DERSet(token.toCMSSignedData().toASN1Structure()));
            AttributeTable existing = signer.getUnsignedAttributes();
            AttributeTable updated = existing == null
                    ? new AttributeTable(new DERSet(tsAttr))
                    : existing.add(tsAttr.getAttrType(), (ASN1Encodable) tsAttr.getAttrValues().getObjectAt(0));
            SignerInformation newSigner = SignerInformation.replaceUnsignedAttributes(signer, updated);
            CMSSignedData newCms = CMSSignedData.replaceSigners(cms, new SignerInformationStore(newSigner));

            byte[] der = newCms.getEncoded(ASN1Encoding.DER);
            String hex = toHex(der);
            if (hex.length() > capacityHexChars) {
                throw new TimestampException("The signature placeholder is too small for the timestamp ("
                        + hex.length() + " > " + capacityHexChars + " hex chars).");
            }
            StringBuilder padded = new StringBuilder(hex);
            while (padded.length() < capacityHexChars) {
                padded.append('0');
            }
            byte[] out = Arrays.copyOf(pdf, pdf.length);
            byte[] hexBytes = padded.toString().getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(hexBytes, 0, out, gapStart + 1, hexBytes.length);
            return out;
        } catch (TimestampException e) {
            throw e;
        } catch (Exception e) {
            throw new TimestampException("Could not add the timestamp: " + e.getMessage(), e);
        }
    }

    private TimeStampToken requestToken(byte[] sha256Imprint) throws TimestampException {
        try {
            TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
            gen.setCertReq(true); // the token must embed the TSA certificate so it can be verified
            TimeStampRequest req = gen.generate(TSPAlgorithms.SHA256, sha256Imprint, new BigInteger(64, new SecureRandom()));

            HttpURLConnection c = (HttpURLConnection) new URL(tsaUrl).openConnection();
            c.setConnectTimeout(timeoutMs);
            c.setReadTimeout(timeoutMs);
            c.setDoOutput(true);
            c.setRequestMethod("POST");
            c.setRequestProperty("Content-Type", "application/timestamp-query");
            c.getOutputStream().write(req.getEncoded());
            c.getOutputStream().close();
            if (c.getResponseCode() != 200) {
                throw new TimestampException("The TSA answered HTTP " + c.getResponseCode() + ".");
            }
            byte[] body = readAll(c.getInputStream());

            TimeStampResponse resp = new TimeStampResponse(body);
            resp.validate(req); // status granted, nonce and imprint match the request
            if (resp.getTimeStampToken() == null) {
                throw new TimestampException("The TSA did not return a token: " + resp.getStatusString());
            }
            return resp.getTimeStampToken();
        } catch (TimestampException e) {
            throw e;
        } catch (Exception e) {
            throw new TimestampException("Time stamping authority unavailable or invalid answer (" + tsaUrl + "): " + e.getMessage(), e);
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format("%02X", x));
        }
        return sb.toString();
    }
}

package spike;

import java.io.File;
import java.nio.file.Files;

import com.google.gson.GsonBuilder;

/**
 * DEV TOOL: verifies a PDF from the command line and prints the result as JSON.
 * Usage: VerifyCli file.pdf [trustDir] [testTrustDir] [HARD|SOFT|OFF revocation] [REQUIRED|OPTIONAL|OFF timestamp] [tsaTrustDir]
 */
public class VerifyCli {

    public static void main(String[] a) throws Exception {
        File trust = new File(a.length > 1 ? a[1] : "../certs/trust");
        File test = new File(a.length > 2 ? a[2] : "../certs/trust-test");
        SignatureVerifier.RevocationMode mode = SignatureVerifier.RevocationMode.valueOf(a.length > 3 ? a[3].toUpperCase() : "HARD");
        SignatureVerifier.TimestampMode tsMode =
                SignatureVerifier.TimestampMode.valueOf(a.length > 4 ? a[4].toUpperCase() : "OPTIONAL");
        File tsaTrust = new File(a.length > 5 ? a[5] : "../certs/trust-tsa");
        SignatureVerifier v = new SignatureVerifier(trust, test, tsaTrust, mode, tsMode);
        System.err.println("anchors=" + v.trustAnchorCount() + " tsaAnchors=" + v.tsaAnchorCount()
                + " revocation=" + v.revocationMode() + " timestamp=" + v.timestampMode());
        SignatureVerifier.Result r = v.verify(null, Files.readAllBytes(new File(a[0]).toPath()));
        System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(r));
    }
}

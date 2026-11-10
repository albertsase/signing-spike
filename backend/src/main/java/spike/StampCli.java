package spike;

import java.io.File;
import java.nio.file.Files;

/**
 * DEV TOOL: adds a timestamp to the last signature of a PDF.
 * Usage: StampCli in.pdf out.pdf tsaUrl [--wrong-imprint]
 * With --wrong-imprint the timestamp is requested for a different hash (to check that the verifier rejects it).
 */
public class StampCli {

    public static void main(String[] a) throws Exception {
        byte[] pdf = Files.readAllBytes(new File(a[0]).toPath());
        SignatureTimestamper t = new SignatureTimestamper(a[2], 15000);
        boolean wrong = a.length > 3 && "--wrong-imprint".equals(a[3]);
        byte[] out = t.addTimestamp(pdf, wrong ? new byte[32] : null);
        Files.write(new File(a[1]).toPath(), out);
        System.out.println("Stamped -> " + a[1] + (wrong ? " (WRONG imprint on purpose)" : ""));
    }
}

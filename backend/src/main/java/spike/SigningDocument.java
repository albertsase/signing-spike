package spike;

import java.util.ArrayList;
import java.util.List;

/** A document in a signature workflow: ordered required signers and the list of PDF versions (one per signature). */
public class SigningDocument {

    public static class Signer {
        public String role;          // e.g. DO, IO
        public String status;        // PENDING | SIGNED
        public String subject;       // certificate subject once signed
        public String fingerprintSha256;
        public String signedAt;      // server time of acceptance
        public Box box;              // where this role's visible signature goes (defined by the PDF template)
    }

    /** Rectangle on a page, PDF points, origin at the lower-left corner of the page. page is 1-based. */
    public static class Box {
        public int page;
        public float llx, lly, urx, ury;

        public Box(int page, float llx, float lly, float urx, float ury) {
            this.page = page;
            this.llx = llx;
            this.lly = lly;
            this.urx = urx;
            this.ury = ury;
        }
    }

    public String id;
    public String title;
    public String status;            // IN_PROGRESS | COMPLETED
    public int version;              // 0 = original PDF without signatures, n = after n signatures
    public List<Signer> signers = new ArrayList<Signer>();

    // not serialised to the client
    public transient List<byte[]> versions = new ArrayList<byte[]>();

    public byte[] currentPdf() {
        return versions.get(versions.size() - 1);
    }

    public Signer nextPending() {
        for (Signer s : signers) {
            if ("PENDING".equals(s.status)) {
                return s;
            }
        }
        return null;
    }
}

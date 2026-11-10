package spike;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;

/**
 * Generates a tiny sample "coordination agreement" PDF. In the real system this is the PDF from the templates.
 *
 * The TEMPLATE decides where each role signs: it draws an empty frame per role and exposes the same rectangle through
 * {@link #boxFor(String)}. The backend sends that rectangle to the front, which passes it to AutoFirma, so the visible
 * signature lands exactly inside the frame. The PDF must be generated ONCE and never regenerated after the first signature.
 */
public class SamplePdf {

    private static final float FRAME_Y0 = 90f;
    private static final float FRAME_Y1 = 160f;

    /** DO on the left half, IO on the right half of an A4 page (595 x 842 pt). Other roles: below, full width. */
    public static SigningDocument.Box boxFor(String role) {
        if ("DO".equals(role)) {
            return new SigningDocument.Box(1, 50f, FRAME_Y0, 290f, FRAME_Y1);
        }
        if ("IO".equals(role)) {
            return new SigningDocument.Box(1, 305f, FRAME_Y0, 545f, FRAME_Y1);
        }
        return new SigningDocument.Box(1, 50f, 20f, 545f, 80f);
    }

    /** DEV TOOL: writes a sample PDF. Usage: SamplePdf out.pdf */
    public static void main(String[] a) throws Exception {
        java.nio.file.Files.write(java.nio.file.Paths.get(a[0]), create("Sample document"));
    }

    public static byte[] create(String title) throws IOException {
        PDDocument doc = new PDDocument();
        try {
            PDPage page = new PDPage(PDRectangle.A4);
            doc.addPage(page);
            PDPageContentStream cs = new PDPageContentStream(doc, page);
            cs.beginText();
            cs.setFont(PDType1Font.HELVETICA_BOLD, 16);
            cs.newLineAtOffset(60, 740);
            cs.showText(title);
            cs.setFont(PDType1Font.HELVETICA, 11);
            cs.newLineAtOffset(0, -30);
            cs.showText("Sample document generated at " + new Date());
            cs.newLineAtOffset(0, -18);
            cs.showText("This PDF must be signed by two parties: Drone Operator (DO) and Infrastructure Operator (IO).");
            cs.newLineAtOffset(0, -18);
            cs.showText("It is frozen once the first signature is added; it must never be regenerated.");
            cs.endText();

            drawFrame(cs, "DO", "Drone Operator (DO)");
            drawFrame(cs, "IO", "Infrastructure Operator (IO)");
            cs.close();

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            return out.toByteArray();
        } finally {
            doc.close();
        }
    }

    private static void drawFrame(PDPageContentStream cs, String role, String label) throws IOException {
        SigningDocument.Box b = boxFor(role);
        cs.setLineWidth(0.7f);
        cs.setStrokingColor(0.55f, 0.55f, 0.55f);
        cs.addRect(b.llx, b.lly, b.urx - b.llx, b.ury - b.lly);
        cs.stroke();
        cs.beginText();
        cs.setFont(PDType1Font.HELVETICA, 9);
        cs.setNonStrokingColor(0.35f, 0.35f, 0.35f);
        cs.newLineAtOffset(b.llx, b.ury + 6f);
        cs.showText("Signature: " + label);
        cs.endText();
        cs.setNonStrokingColor(0f, 0f, 0f);
    }
}

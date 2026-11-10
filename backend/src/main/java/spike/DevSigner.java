package spike;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;

import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * DEV TOOL ONLY. Adds an incremental PAdES-like signature with a .p12 file, so the whole flow can be tested
 * without AutoFirma (in the real flow AutoFirma does this on the user's machine and the key never leaves it).
 *
 * Usage: DevSigner in.pdf out.pdf keystore.p12 password "reason"
 */
public class DevSigner {

    public static void main(String[] a) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        sign(new File(a[0]), new File(a[1]), new File(a[2]), a[3], a.length > 4 ? a[4] : "Test signature");
        System.out.println("Signed -> " + a[1]);
    }

    public static void sign(File in, File out, File p12, String password, String reason) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        InputStream ksIn = new FileInputStream(p12);
        try {
            ks.load(ksIn, password.toCharArray());
        } finally {
            ksIn.close();
        }
        String alias = ks.aliases().nextElement();
        final PrivateKey key = (PrivateKey) ks.getKey(alias, password.toCharArray());
        final Certificate[] chain = ks.getCertificateChain(alias);
        final X509Certificate cert = (X509Certificate) chain[0];

        PDDocument doc = PDDocument.load(in);
        FileOutputStream fos = new FileOutputStream(out);
        try {
            PDSignature sig = new PDSignature();
            sig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            sig.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            sig.setName(cert.getSubjectX500Principal().getName());
            sig.setReason(reason);
            sig.setSignDate(Calendar.getInstance());

            SignatureInterface si = new SignatureInterface() {
                @Override
                public byte[] sign(InputStream content) throws java.io.IOException {
                    try {
                        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                        ContentSigner cs = new JcaContentSignerBuilder("SHA256WithRSA").build(key);
                        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                                new JcaDigestCalculatorProviderBuilder().build()).build(cs, cert));
                        gen.addCertificates(new JcaCertStore(Arrays.asList(chain)));
                        CMSSignedData d = gen.generate(new CMSProcessableByteArray(IOUtils.toByteArray(content)), false);
                        return d.getEncoded();
                    } catch (Exception e) {
                        throw new java.io.IOException(e);
                    }
                }
            };

            SignatureOptions opts = new SignatureOptions();
            opts.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);
            doc.addSignature(sig, si, opts);
            doc.saveIncremental(fos);
            opts.close();
        } finally {
            fos.close();
            doc.close();
        }
    }
}

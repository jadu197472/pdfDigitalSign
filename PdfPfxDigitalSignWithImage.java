package heps.eps.misreceive.web;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import com.itextpdf.io.image.ImageData;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.xmp.XMPConst;
import com.itextpdf.kernel.xmp.XMPMeta;
import com.itextpdf.kernel.xmp.XMPMetaFactory;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;

/*
 * 정상 작동 - 이미지 + 전자서명(.pfx) : itextpdf(AGPLv3 license)
 */
public class PdfPfxDigitalSignWithImage {
    public static void main(String[] args) throws Exception {
        String srcPdf = "D:\\jd-gui-1.6.6\\input\\sample.pdf";
        String destPdf = "D:\\jd-gui-1.6.6\\output\\signed_image_pfx.pdf";
        String signImage = "D:\\jd-gui-1.6.6\\image\\sample.png";

        String signCert = "D:\\jd-gui-1.6.6\\cert\\kica\\signCert.p12.pfx";
        String signPass = "signgate1!";
        String alias = "1"; //keyStore 에 인증서가 1개뿐인경우, 기본값은 1

        // 1. KeyStore 로드
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream(signCert), signPass.toCharArray());

        if( ks == null ) System.out.println("ks >>>> null!!");
        else System.out.println("ks >>>> not null!!");
        
        PrivateKey pk = (PrivateKey) ks.getKey(alias, signPass.toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);

        if( pk == null ) System.out.println("pk >>>> null!!");
        else System.out.println("pk >>>> not null!!");

        // 2. PdfSigner 생성
        PdfReader reader = new PdfReader(srcPdf);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(destPdf), new StampingProperties());

        System.out.println("reader.getFileLength() >>>> " + reader.getFileLength());
        System.out.println("signer.getDocument().getNumberOfPages() >>>> " + signer.getDocument().getNumberOfPages());

        //XMP metadata : AGPLv3 license start
        XMPMeta xmp = XMPMetaFactory.create();
        xmp.setProperty(XMPConst.NS_DC, "rights", "This PDF was generated using iText under AGPLv3 license.");
        xmp.setProperty(XMPConst.NS_DC, "description", "Source code available according to AGPLv3.");
        signer.getDocument().setXmpMetadata(xmp);
        //XMP metadata : AGPLv3 license end

        float x = 100;				// 왼쪽에서 100pt
        float y = 100;				// 아래에서 100pt
        float topMargin = 50;		// 위에서 50pt 떨어짐
        float rightMargin = 50;		// 오른쪽에서 50pt 떨어짐
        float width = 100;
        float height = 100;

        float pageWidth = signer.getDocument().getFirstPage().getPageSize().getWidth();
        float pageHeight = signer.getDocument().getFirstPage().getPageSize().getHeight();

        x = pageWidth - rightMargin - width;
        y = pageHeight - topMargin - height;

        ImageData imageData = null;
        imageData = com.itextpdf.io.image.ImageDataFactory.create(signImage);

        // 3. 서명 appearance 설정
        PdfSignatureAppearance appearance = signer.getSignatureAppearance()
			.setReason("문서 승인")
			.setLocation("Seoul, Korea")
			.setReuseAppearance(false)
			.setPageRect(new com.itextpdf.kernel.geom.Rectangle(x, y, width, height)) // 위치와 크기
			.setPageNumber(1)
			.setSignatureGraphic( com.itextpdf.io.image.ImageDataFactory.create(signImage) )
			.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC); // 이미지 표시

        signer.setFieldName("sig");

        // 4. ExternalSignature & Digest
        //IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", "BC");
        IExternalSignature pks = new PrivateKeySignature(pk, "SHA256", null);
        IExternalDigest digest = new BouncyCastleDigest();

        // 5. PDF 서명 적용
        signer.signDetached(digest, pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);

        System.out.println("PDF pfx 이미지 서명 완료: " + destPdf);
    }
}




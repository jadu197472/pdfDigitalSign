package heps.eps.misreceive.web;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/*
 * 정상 작동 - 전자서명(pfx) 만 : pdfbox, bouncycastle
 */
public class PdfBasicDigitalSign {
    public static void main(String[] args) throws Exception {
        String srcPdf = "D:\\jd-gui-1.6.6\\input\\sample.pdf";
        String destPdf = "D:\\jd-gui-1.6.6\\output\\signed_basic_pfx.pdf";
        //String signImage = "D:\\jd-gui-1.6.6\\image\\sample.png";

        String signCert = "D:\\jd-gui-1.6.6\\cert\\kica\\signCert.p12.pfx";
        String signPass = "signgate1!";
        String alias = "1"; //keyStore 에 인증서가 1개뿐인경우, 기본값은 1

        // 1. 키스토어 로드
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(signCert), signPass.toCharArray());

        alias = keyStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, signPass.toCharArray());
        Certificate[] certChain = keyStore.getCertificateChain(alias);

        // 2. PDF 로드
        PDDocument document = PDDocument.load(new File(srcPdf));

        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName("Hong Gil-dong");
        signature.setReason("Contract Approval");
        signature.setLocation("Seoul");
        signature.setSignDate(Calendar.getInstance());

        document.addSignature(signature);

        // 3. Incremental + External Signing
        try (FileOutputStream fos = new FileOutputStream(destPdf)) {
            ExternalSigningSupport externalSigning = document.saveIncrementalForExternalSigning(fos);

            byte[] content = IOUtils.toByteArray(externalSigning.getContent());

            // 4. PKCS#7 서명 생성
            byte[] cmsSignature = sign(content, privateKey, certChain);

            // 5. PDF에 서명값 포함
            externalSigning.setSignature(cmsSignature);
        }

        document.close();

        System.out.println("PDF basic 서명 완료: " + destPdf);
    }

    private static byte[] sign(byte[] content, PrivateKey privateKey, Certificate[] certChain) throws Exception {
        List<X509Certificate> certList = new ArrayList<>();
        for (Certificate cert : certChain) {
            certList.add((X509Certificate) cert);
        }

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().build()
                ).build( new JcaContentSignerBuilder("SHA256withRSA").build(privateKey), certList.get(0) )
        );

        gen.addCertificates(new JcaCertStore(certList));

        CMSSignedData signedData = gen.generate(
                new CMSProcessableByteArray(content),
                false   // detached
        );

        return signedData.getEncoded();
    }
}




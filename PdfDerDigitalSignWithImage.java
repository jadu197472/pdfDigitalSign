package heps.eps.misreceive.web;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
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
 * 정상 작동 - 이미지 + 전자서명(.der) : itextpdf(AGPLv3 license), bouncycastle
 */
public class PdfDerDigitalSignWithImage {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        String srcPdf = "D:\\jd-gui-1.6.6\\input\\sample.pdf";
        String destPdf = "D:\\jd-gui-1.6.6\\output\\signed_image_der.pdf";
        String signImage = "D:\\jd-gui-1.6.6\\image\\sample.png";

        String signCert = "D:\\jd-gui-1.6.6\\cert\\kica\\signCert.der";
        String signKey = "D:\\jd-gui-1.6.6\\cert\\kica\\signPri.key";
        String signPass = "signgate1!";
        //String alias = "1"; //keyStore 에 인증서가 1개뿐인경우, 기본값은 1
        
        X509Certificate cert = loadCertificate(signCert);
        System.out.println("cert >>>> " + cert.getIssuerX500Principal());        
        
        PrivateKey privateKey = loadPrivateKey(signKey, signPass);

        signPdf(srcPdf, destPdf, signImage, privateKey, cert);

        System.out.println("PDF der 이미지 서명 완료: " + destPdf);
    }

    // 인증서 로드
    static X509Certificate loadCertificate(String path) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream is = new FileInputStream(path)) {
            return (X509Certificate) cf.generateCertificate(is);
        }
    }

    // NPKI PrivateKey 로드
    static PrivateKey loadPrivateKey(String signKey, String signPass) throws Exception {
        byte[] keyData = Files.readAllBytes(Paths.get(signKey));

        ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(keyData);
        ASN1Sequence algSeq = (ASN1Sequence) seq.getObjectAt(0);
        ASN1OctetString encryptedKey = (ASN1OctetString) seq.getObjectAt(1);

        ASN1Sequence params = (ASN1Sequence) algSeq.getObjectAt(1);

        byte[] salt = ((ASN1OctetString) params.getObjectAt(0)).getOctets();
        int iteration = ((ASN1Integer) params.getObjectAt(1)).getValue().intValue();
        
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

        byte[] pwBytes = signPass.getBytes("UTF-8");

        byte[] input = new byte[pwBytes.length + salt.length];
        System.arraycopy(pwBytes, 0, input, 0, pwBytes.length);
        System.arraycopy(salt, 0, input, pwBytes.length, salt.length);

        byte[] digest = sha1.digest(input);

        for (int i = 1; i < iteration; i++) {
            digest = sha1.digest(digest);
        }

        System.out.println("salt length = " + salt.length);
        System.out.println("iteration = " + iteration);
        System.out.println("digest length = " + digest.length);

        // key
        byte[] key = Arrays.copyOfRange(digest, 0, 16);

        // IV 생성
        byte[] ivSeed = new byte[4 + salt.length];
        System.arraycopy(digest, 16, ivSeed, 0, 4);
        System.arraycopy(salt, 0, ivSeed, 4, salt.length);

        byte[] ivHash = sha1.digest(ivSeed);
        byte[] iv = Arrays.copyOfRange(ivHash, 0, 16);

        Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", "BC");

        SecretKeySpec keySpec = new SecretKeySpec(key, "SEED");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decrypted = cipher.doFinal(encryptedKey.getOctets());
        System.out.println("decrypted.length = " + decrypted.length);
        System.out.println("decrypted[0] = " + decrypted[0]);

        //byte[] asn1Key = extractASN1_del(decrypted);
        //byte[] asn1Key = trimASN1_del(decrypted);

        int offset = 26; // 이미 확인됨
        byte[] rsaKey = extractRSA(decrypted, offset);        

        System.out.println("rsaKey.length = " + rsaKey.length);
        System.out.println("rsaKey start = " + rsaKey[0]);

        /*
        int offset = -1;
        for (int i = 0; i < asn1Key.length - 1; i++) {
            if (asn1Key[i] == 0x30) {
                offset = i;
                break;
            }
        }
        System.out.println("offset = " + offset);
        System.out.println(String.format("%02X %02X %02X %02X", asn1Key[offset], asn1Key[offset + 1], asn1Key[offset + 2], asn1Key[offset + 3]));
        */

        PrivateKey privateKey = parsePrivateKey(rsaKey);

        return privateKey;
    }

    static byte[] extractRSA(byte[] decrypted, int offset) {
        int length = ((decrypted[offset + 2] & 0xff) << 8) | (decrypted[offset + 3] & 0xff);

        int totalLen = length + 4;

        return Arrays.copyOfRange(decrypted, offset, offset + totalLen);
    }

    // PBKDF1 구현
    static byte[] pbkdf1(byte[] signPass, byte[] salt, int iteration, int dkLen) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

        sha1.update(signPass);
        sha1.update(salt);

        byte[] hash = sha1.digest();

        for (int i = 1; i < iteration; i++) {
            hash = sha1.digest(hash);
        }

        return Arrays.copyOf(hash, dkLen);
    }

    static PrivateKey parsePrivateKey(byte[] keyBytes) throws Exception {
        try {
            // PKCS8 시도
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        } catch (Exception e) {
            // PKCS1 처리
            //ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(keyBytes);

        	ASN1InputStream asn1InputStream = new ASN1InputStream(keyBytes);
        	ASN1Primitive obj = asn1InputStream.readObject();
        	ASN1Sequence seq = (ASN1Sequence) obj;

            org.bouncycastle.asn1.pkcs.RSAPrivateKey rsa = org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(seq);

            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
				rsa.getModulus(),
				rsa.getPublicExponent(),
				rsa.getPrivateExponent(),
				rsa.getPrime1(),
				rsa.getPrime2(),
				rsa.getExponent1(),
				rsa.getExponent2(),
				rsa.getCoefficient()
            );

            KeyFactory kf = KeyFactory.getInstance("RSA");
            
            asn1InputStream.close();

            return kf.generatePrivate(keySpec);
        }
    }

    // PDF 서명
    static void signPdf( String srcPdf, String destPdf, String imagePath, PrivateKey privateKey, X509Certificate cert ) throws Exception {
        Certificate[] chain = new Certificate[]{cert};

        PdfReader reader = new PdfReader(srcPdf);
        PdfWriter writer = new PdfWriter(destPdf);

        PdfSigner signer = new PdfSigner(reader, writer, new StampingProperties());
        
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
        
        //Rectangle rect = new Rectangle(36, 648, 200, 100);
        Rectangle rect = new Rectangle(x, y, width, height);

        signer.getSignatureAppearance()
			.setReason("전자서명")
			.setLocation("Seoul, Korea")
			.setReuseAppearance(false)
			.setPageRect(rect)
			.setPageNumber(1)
			.setSignatureGraphic(ImageDataFactory.create(imagePath))
			.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);

        signer.setFieldName("signature1");

        IExternalSignature signature = new PrivateKeySignature(privateKey, "SHA256", "BC");

        IExternalDigest digest = new BouncyCastleDigest();

        signer.signDetached(
			digest,
			signature,
			chain,
			null,
			null,
			null,
			0,
			PdfSigner.CryptoStandard.CMS
        );
    }







    static byte[] trimASN1_del(byte[] data) {
        int length = ((data[2] & 0xff) << 8) | (data[3] & 0xff);
        int totalLen = length + 4;

        return Arrays.copyOfRange(data, 0, totalLen);
    }

    static byte[] extractASN1_del(byte[] data) {
    	System.out.println("data.length = " + data.length);
    	System.out.println("-------------------------------");

        for (int i = 0; i < data.length - 2; i++) {
            if (data[i] == 0x30) { // ASN1 SEQUENCE
                int lengthByte = data[i + 1] & 0xff;
                int length;
                int headerLen;

                if ((lengthByte & 0x80) == 0) {
                    // short form
                    length = lengthByte;
                    headerLen = 2;
                } else {
                    // long form
                    int numBytes = lengthByte & 0x7f;
                    if (numBytes > 4) continue;

                    length = 0;
                    for (int j = 0; j < numBytes; j++) {
                        length = (length << 8) | (data[i + 2 + j] & 0xff);
                    }
                    headerLen = 2 + numBytes;
                }

                System.out.println("headerLen = " + headerLen);
                System.out.println("length = " + length);
                System.out.println("-------------------------------");

                int totalLen = headerLen + length;

                if (i + totalLen <= data.length) {
                	System.out.println("data.length = " + data.length);
                	System.out.println("i = " + i);
                	System.out.println("totalLen = " + totalLen);

                    return Arrays.copyOfRange(data, i, i + totalLen);
                }
            }
        }

        throw new RuntimeException("ASN1 not found");
    }

    // NPKI PrivateKey 로드 del
    static PrivateKey loadPrivateKey_del(String signKey, String signPass) throws Exception {
        byte[] keyData = Files.readAllBytes(Paths.get(signKey));

        ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(keyData);
        ASN1Sequence algSeq = (ASN1Sequence) seq.getObjectAt(0);
        ASN1OctetString encryptedKey = (ASN1OctetString) seq.getObjectAt(1);

        ASN1Sequence params = (ASN1Sequence) algSeq.getObjectAt(1);

        byte[] salt = ((ASN1OctetString) params.getObjectAt(0)).getOctets();
        int iteration = ((ASN1Integer) params.getObjectAt(1)).getValue().intValue();

        /*
        byte[] key = pbkdf1(signPass.getBytes("UTF-8"), salt, iteration, 16);

        byte[] iv;
        if (params.size() > 2) {
            iv = ((ASN1OctetString) params.getObjectAt(2)).getOctets();
        } else {
            iv = Arrays.copyOf(key, 16);
        }

        Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", "BC");
        SecretKeySpec keySpec = new SecretKeySpec(key, "SEED");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decrypted = cipher.doFinal(encryptedKey.getOctets());
        */

        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

        sha1.update(signPass.getBytes("UTF-8"));
        sha1.update(salt);

        byte[] digest = sha1.digest();

        for (int i = 1; i < iteration; i++) {
            digest = sha1.digest(digest);
        }

        // SEED key
        byte[] keyBytes = Arrays.copyOfRange(digest, 0, 16);

        // 🔥 KICA signGATE 방식 IV
        byte[] iv = new byte[16];
        System.arraycopy(digest, 16, iv, 0, 4);
        System.arraycopy(digest, 0, iv, 4, 12);

        Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", "BC");

        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "SEED");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decrypted = cipher.doFinal(encryptedKey.getOctets());

        System.out.println("salt length = " + salt.length);
        System.out.println("iteration = " + iteration);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        //return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decrypted));
        return parsePrivateKey(decrypted);
    }
}








package de.tsenger.vdstools;


import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.datamatrix.DataMatrixWriter;
import de.tsenger.vdstools.vds.DigitalSeal;
import de.tsenger.vdstools.vds.VdsHeader;
import de.tsenger.vdstools.vds.VdsMessage;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDate;
import java.util.Enumeration;


public class Main {
    public static byte[] convertBitMatrixToByteArray(BitMatrix bitMatrix, String format) throws Exception {
        // Validate format
        if (!format.equalsIgnoreCase("PNG") && !format.equalsIgnoreCase("JPEG")) {
            throw new IllegalArgumentException("Unsupported image format: " + format);
        }

        // Convert BitMatrix to BufferedImage
        int width = bitMatrix.getWidth();
        int height = bitMatrix.getHeight();
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);

        for (int x = 0; x < width; x++) {
            for (int y = 0; y < height; y++) {
                image.setRGB(x, y, bitMatrix.get(x, y) ? 0xFF000000 : 0xFFFFFFFF); // Black or white
            }
        }

        // Write BufferedImage to ByteArrayOutputStream
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            boolean success = ImageIO.write(image, format, baos);
            if (!success) {
                throw new RuntimeException("Failed to write image in format: " + format);
            }
            return baos.toByteArray();
        }
    }

    public static void main(String[] args) {
        try {
            String password_ = "bccca";
            FileInputStream fis = new FileInputStream("/Users/bccca/Desktop/ahad_cert.p12");

            // Initialize KeyStore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(fis, password_.toCharArray());
            Enumeration<String> aliases = keyStore.aliases();

            // Iterate through aliases and print certificates
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                PrivateKey key = (PrivateKey) keyStore.getKey(alias,password_.toCharArray());
                Signer signer = new Signer(key);
                VdsHeader header = new VdsHeader.Builder("ARRIVAL_ATTESTATION")
                        .setIssuingCountry("D<<")
                        .setSignerIdentifier("DETS")
                        .setCertificateReference("32")
                        .setIssuingDate(LocalDate.parse("2024-09-27"))
                        .setSigDate(LocalDate.parse("2024-09-27"))
                        .build();

                String mrz = "MED<<MANNSENS<<MANNY<<<<<<<<<<<<<<<<6525845096USA7008038M2201018<<<<<<06";
                String azr = "ABC123456DEF";
                VdsMessage vdsMessage = new VdsMessage.Builder(header.getVdsType())
                        .addDocumentFeature("MRZ", mrz)
                        .addDocumentFeature("AZR", azr)
                        .build();

                DigitalSeal digitalSeal = new DigitalSeal(header, vdsMessage, signer);

                byte[] encodedBytes = digitalSeal.getEncoded();

                DataMatrixWriter dmw = new DataMatrixWriter();
                BitMatrix bitMatrix = dmw.encode(DataEncoder.encodeBase256(digitalSeal.getEncoded()), BarcodeFormat.DATA_MATRIX,
                        450, 450);
                Path path = Path.of("/Users/bccca/Desktop/vdstools/test.png");
                MatrixToImageWriter.writeToPath(bitMatrix, "PNG", path);


                //verify
                //byte[] byteArray = convertBitMatrixToByteArray(bitMatrix, "PNG");

                DigitalSeal digitalSealToVerify = DigitalSeal.fromByteArray(encodedBytes);
                String vdsType = digitalSeal.getVdsType();

// getFeature() returns an Optional<Feature> which can be used as follows
                String mrzToVerify = digitalSealToVerify.getFeature("MRZ").get().valueStr();
                String azrToVerify = digitalSealToVerify.getFeature("AZR").get().valueStr();
                if(digitalSealToVerify.getFeature("FACE_IMAGE").isPresent() ){
                    byte[] imgBytes = digitalSealToVerify.getFeature("FACE_IMAGE").get().valueBytes();
                }
                String signerCertRef = digitalSealToVerify.getSignerCertRef();
                Verifier verifier = new Verifier(digitalSealToVerify, cert);
                Verifier.Result result = verifier.verify();
                System.out.println(result.toString());

// or get all available Features in one List<Feature>
//                Map<String,Feature> featureMap = digitalSeal.getFeatureMap();
//                for (Feature feature: featureMap.values()) {
//                    System.out.println(feature.name() + ", " + feature.coding() + ", " + feature.valueStr());
//                }

                // Define your own export Path and uncomment if needed
//		Path path = Path.of("test/test.png");
//		MatrixToImageWriter.writeToPath(bitMatrix, "PNG", path);


                // Define your own export Path and uncomment if needed
//		Path path = Path.of("test/test.png");
//		MatrixToImageWriter.writeToPath(bitMatrix, "PNG", path);




            }
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
}
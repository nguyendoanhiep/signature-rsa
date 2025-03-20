package com.example.signature.controller;

import com.example.signature.RSA;
import com.example.signature.dto.Request;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api")
public class Controller {

    @GetMapping(value = "/sign")
    public ResponseEntity<?> sign(@RequestParam String data) throws Exception {
        try {
            String privateKeyString = new String(Files.readAllBytes(Paths.get("D:\\MKG\\personal-project\\Signature\\src\\main\\java\\com\\example\\signature\\key_pair\\private_key.pem")));
            String getPrivateKey = privateKeyString
                    .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll("-----END PRIVATE KEY-----", "")
                    .replaceAll("\r\n", "")
                    .replaceAll("\n", "");
            byte[] privateKeyAsByte = Base64.getDecoder().decode(getPrivateKey);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyAsByte);

            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signatureByByte = signature.sign();
            return ResponseEntity.ok(Base64.getEncoder().encodeToString(signatureByByte));
        } catch (Exception ex) {
            ex.printStackTrace();
            return ResponseEntity.ok("EX");
        }
    }

    @PostMapping(value = "/verify")
    public ResponseEntity<?> verify(@RequestBody Request request) {
        try {
            String publicKeyByString = new String(Files.readAllBytes(Paths.get("D:\\MKG\\personal-project\\Signature\\src\\main\\java\\com\\example\\signature\\key_pair\\public_key.pem")));
            String getPublicKey = publicKeyByString
                    .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll("-----END PUBLIC KEY-----", "")
                    .replaceAll("\r\n", "")
                    .replaceAll("\n", "");
            byte[] publicKeyAsByte = Base64.getDecoder().decode(getPublicKey);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyAsByte);
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);

            Signature publicSignature = Signature.getInstance("SHA256withRSA");
            publicSignature.initVerify(publicKey);
            publicSignature.update(request.getData().getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = Base64.getDecoder().decode(request.getSignatureByPrivateKey());
            return ResponseEntity.ok(publicSignature.verify(signatureBytes));
        } catch (Exception ex) {
            ex.printStackTrace();
            return ResponseEntity.ok("EX");
        }
    }
    @GetMapping(value = "/test")
    public void test(@RequestParam String data) throws Exception {
        KeyPair rsaKeypair = RSA.generateKeyPair(3072);

        String dataEncrypted = RSA.encrypt(data, rsaKeypair.getPublic());

        String dataDecrypted = RSA.decrypt(dataEncrypted, rsaKeypair.getPrivate());

        String signedData = RSA.sign(data, rsaKeypair.getPrivate());

        boolean verity = RSA.verify(data, signedData, rsaKeypair.getPublic());

        System.out.println("dataEncrypt: " + dataEncrypted );
        System.out.println("dataDeccrypt: " +  dataDecrypted);
        System.out.println("verity: "+  verity  );
    }
}

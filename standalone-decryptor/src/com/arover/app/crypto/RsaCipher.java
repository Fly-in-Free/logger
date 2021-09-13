package com.arover.app.crypto;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * @author MZY
 * created at 2021/3/13 16:45
 */
public class RsaCipher {

    public static byte[] decrypt(byte[] encrypted, byte[] privateKey) {

        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
            KeyFactory kf = null;
            kf = KeyFactory.getInstance("RSA");
            PrivateKey keyPrivate = kf.generatePrivate(keySpec);
            
            OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            Cipher cp = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cp.init(Cipher.DECRYPT_MODE, keyPrivate, oaepParameterSpec);
            
            return cp.doFinal(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return encrypted;
        }
    }

}

package com.example.aes;

import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class AESUtilsTest {

    private static final int AES_KEY_SIZE = 256;

    private static final int GCM_IV_LENGTH = 12;

    private static final int GCM_TAG_LENGTH = 16;


    /**
     * 获取盐值，保存在aes.properties
     */
    @Test
    public void getCommonIv() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        System.out.println(iv.toString());
    }

    /**
     * 获取秘钥，保存在aes.properties
     */
    @Test
    public void getSecretKey() {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }

        keyGenerator.init(AES_KEY_SIZE);

        SecretKey secretKey = keyGenerator.generateKey();

        String encodeKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        System.out.println(encodeKey);
    }

    /**
     * 明文生成密文
     */
    @Test
    public void testEncrypt() {
        String encrypt = AESUtils.encrypt("123456");
        System.out.println(encrypt);
    }

    /**
     * 密文解密为明文
     */
    @Test
    public void testDecrypt() {
        String decrypt = AESUtils.decrypt("fW4y4InqNAOVqWRJHhxZ207xdUIadg==");
        System.out.println(decrypt);
    }

}

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.lang.model.element.VariableElement;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * @ClassName: AES/GCM加密工具类
 * @Description:
 * @Author: Macay
 * @Date: 2021/9/13 11:05 下午
 */
public class AESUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(AESUtils.class);

    private static final int AES_KEY_SIZE = 256;

    private static final int GCM_IV_LENGTH = 12;

    private static final int GCM_TAG_LENGTH = 16;


    public static void main(String[] args) {
        SecretKey secretKey = getSecretKey();
        byte[] ivByte = getIVByte();
        String encrypt = encrypt("Huawei@123", secretKey, ivByte);
        System.out.println(encrypt);

        String decrypt = decrypt(encrypt, secretKey, ivByte);
        System.out.println(decrypt);
    }


    /**
     * 生成加密密钥
     * @return
     */
    public static SecretKey getSecretKey() {

        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.error("get keyGenerator has error, exception is {}", ex.getMessage());
        }

        keyGenerator.init(AES_KEY_SIZE);

        SecretKey secretKey = keyGenerator.generateKey();

        String encodeKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

        byte[] decodeKey = Base64.getDecoder().decode(encodeKey);

        SecretKeySpec originalKey = new SecretKeySpec(decodeKey, 0, decodeKey.length, "AES");

        return originalKey;
    }


    public static byte[] getIVByte() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return iv;
    }

    public static String encrypt(String str) {
        return encrypt(str, getSecretKey(), getIVByte());
    }

    public static String encrypt(String str, SecretKey key, byte[] iv) {
        String result = "";
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            byte[] bytes = cipher.doFinal(str.getBytes("utf-8"));
            result = Base64.getEncoder().encodeToString(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return result;

    }

    public static String decrypt(String str) {
        return null;
    }

    public static String decrypt(String str, SecretKey key, byte[] iv) {
        byte[] bytes = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            bytes = cipher.doFinal(Base64.getDecoder().decode(str));
            return new String(bytes, "utf-8");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }
}

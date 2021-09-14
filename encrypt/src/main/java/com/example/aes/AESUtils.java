package com.example.aes;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;

/**
 * @ClassName: AES/GCM加密工具类
 * @Description: 将随机生成的秘钥和盐值保存在配置文件中用于加解密， 同一个密码的加解密使用相同的配置,与测试类配合使用，为安全，定期获取新秘钥盐值修改配置文件
 * @Author: Macay
 * @Date: 2021/9/13 11:05 下午
 */
public class AESUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(AESUtils.class);

    private static final int AES_KEY_SIZE = 256;

    private static final int GCM_IV_LENGTH = 12;

    private static final int GCM_TAG_LENGTH = 16;

    private static final Properties PROP = new Properties();

    private static InputStream IN = null;

    // 读取配置文件
    static {
        IN = AESUtils.class.getClassLoader().getResourceAsStream("aes.properties");
        try {
            PROP.load(IN);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /**
     * 生成加密密钥
     *
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

    /**
     * 从配置文件中读取秘钥
     *
     * @return
     */
    public static SecretKey getCommonKeyFromConfig() {
        String propertyKey = PROP.getProperty("aes.common.key");
        byte[] decodeKey = Base64.getDecoder().decode(propertyKey);
        SecretKeySpec originalKey = new SecretKeySpec(decodeKey, 0, decodeKey.length, "AES");
        return originalKey;
    }


    /**
     * 生成盐值
     *
     * @return
     */
    public static byte[] getIVByte() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        System.out.println(iv.toString());
        return iv;
    }

    /**
     * 从配置文件中读取盐值
     *
     * @return
     */
    public static byte[] getCommonIvByConfig() {
        String propertyIv = PROP.getProperty("aes.common.iv");
        byte[] bytes = propertyIv.getBytes();
        return bytes;
    }

    /**
     * 加密
     *
     * @param str 密码明文字符串
     * @return
     */
    public static String encrypt(String str) {
        LOGGER.info("start to encrypt");
        return encrypt(str, getCommonKeyFromConfig(), getCommonIvByConfig());
    }

    /**
     * 加密，重载方法
     *
     * @param str 密码明文字符串
     * @param key 秘钥
     * @param iv  盐值
     * @return
     */
    public static String encrypt(String str, SecretKey key, byte[] iv) {
        String result = "";
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            byte[] bytes = cipher.doFinal(str.getBytes("utf-8"));
            result = Base64.getEncoder().encodeToString(bytes);

            // catch中的异常可以合并
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException | InvalidKeyException
                ex) {
            LOGGER.error("encrypt is error, exception is {}", ex.getMessage());
        }
        return result;

    }

    /**
     * 解密
     *
     * @param str 密码密文字符串
     * @return
     */
    public static String decrypt(String str) {
        return decrypt(str, getCommonKeyFromConfig(), getCommonIvByConfig());
    }

    /**
     * 解密
     *
     * @param str 密码密文字符串
     * @param key 秘钥
     * @param iv  盐值
     * @return
     */
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

package com.vitaliy.encryption.encryption;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import com.google.gson.Gson;
import com.scottyab.aescrypt.AESCrypt;
import com.vitaliy.data.TouchData;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.util.Calendar;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import static com.vitaliy.encryption.injection.module.EncryptionModule.KEYSTORE_PROVIDER;

/**
 * Created by vitaliy on 25.05.17.
 */

public class Encryption {
    private static final String AES_KEY_ALIAS = "AES_KEY_ALIAS";
    private static final int IV_LENGTH = 16;
    private static final int GCM_TAG_LENGTH = 128;
    private static final String AES_CIPHER = KeyProperties.KEY_ALGORITHM_AES + "/" +
            KeyProperties.BLOCK_MODE_GCM + "/" + KeyProperties.ENCRYPTION_PADDING_NONE;
    private final Gson gson;
    private final KeyStore keyStore;

    private static final int AES_KEY_SIZE = 256;
    private static final int RSA_KEY_SIZE = 2048;
    private static final String ALGORITHM_AES = KeyProperties.KEY_ALGORITHM_AES;
    private static final String ALGORITHM_RSA = KeyProperties.KEY_ALGORITHM_RSA;
    private static final String RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";
    private static final Charset CHARSET = StandardCharsets.UTF_8;

    private static byte[] encryptedAES = new byte[0];
    private static byte[] encryptedIV = new byte[0];
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private byte[] originalIV = new byte[0];

    public Encryption(Gson gson, KeyStore keyStore) {
        this.gson = gson;
        this.keyStore = keyStore;
        generateAESKeyAndSaveToKeystore();
        originalIV = generateRandomIV();
        encryptedIV = encryptWithRSA(originalIV);
    }

    private void generateAESKeyAndSaveToKeystore() {
        try {
            if (!hasAESKeyInKeystore(AES_KEY_ALIAS)) {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 25);
                KeyGenerator keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER);
                KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(AES_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setCertificateSubject(new X500Principal("CN = Secured Preference Store, O = Devliving Online"))
                        .setCertificateSerialNumber(BigInteger.ONE)
                        .setKeySize(GCM_TAG_LENGTH)
                        .setKeyValidityEnd(end.getTime())
                        .setKeyValidityStart(start.getTime())
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setRandomizedEncryptionRequired(false)
                        .build();
                keyGen.init(spec);
                keyGen.generateKey();
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    private boolean hasAESKeyInKeystore(final String ALIAS) {
        try {
            return keyStore.containsAlias(ALIAS) && keyStore.entryInstanceOf(ALIAS, KeyStore.SecretKeyEntry.class);
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return false;
        }
    }

    private SecretKey getAESKeyFromKeystore() {
        try {
            if (hasAESKeyInKeystore(AES_KEY_ALIAS)) {
                final KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry(AES_KEY_ALIAS, null);
                return entry.getSecretKey();
            } else {
                return null;
            }
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableEntryException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String encrypt(String data) {
        try {
            final byte[] message = gson.toJson(data).getBytes(StandardCharsets.UTF_8);
            final Cipher cipher = Cipher.getInstance(AES_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, getAESKeyFromKeystore(), new GCMParameterSpec(GCM_TAG_LENGTH, originalIV));
            byte[] encodedBytes = cipher.doFinal(message);
            return Base64.encodeToString(encodedBytes, Base64.DEFAULT);
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String decrypt(String data) {
        try {
            final byte[] base64EncryptedMessage = Base64.decode(data, Base64.NO_WRAP);
            final Cipher cipher = Cipher.getInstance(AES_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, getAESKeyFromKeystore(), new GCMParameterSpec(GCM_TAG_LENGTH, originalIV));
            final byte[] mDecrypt = cipher.doFinal(base64EncryptedMessage);
            return new String(mDecrypt, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Assignment Second Part
     */

    public String encryptTouchData(TouchData touchData) {
        try {
            byte[] message = gson.toJson(touchData).getBytes(CHARSET);
            byte[] encryptedMsg = AESCrypt.encrypt(getRandomSecureKey(), originalIV, message);
            return Base64.encodeToString(encryptedMsg, Base64.NO_WRAP);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String decryptTouchData(String message) {
        byte[] base64EncryptedMessage = Base64.decode(message, Base64.NO_WRAP);
        try {
            SecretKeySpec key = new SecretKeySpec(decryptWithRSA(encryptedAES), 0, IV_LENGTH, ALGORITHM_AES);
            byte[] decrypt = AESCrypt.decrypt(key, originalIV, base64EncryptedMessage);
            return new String(decrypt, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return "";
        }
    }

    private SecretKeySpec getRandomSecureKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_AES);
            keyGen.init(AES_KEY_SIZE);
            byte[] randomSecureKey = keyGen.generateKey().getEncoded();
            encryptedAES = encryptWithRSA(randomSecureKey);
            return new SecretKeySpec(randomSecureKey, 0, IV_LENGTH, ALGORITHM_AES);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] generateRandomIV() {
        byte[] bytes = new byte[IV_LENGTH];
        new Random().nextBytes(bytes);
        return bytes;
    }

    public byte[] encryptWithRSA(byte[] bytes) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM_RSA);
            kpg.initialize(RSA_KEY_SIZE);
            KeyPair keyPair = kpg.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
            Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(bytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] decryptWithRSA(byte[] bytes) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(bytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String getEncryptedAES() {
        return Base64.encodeToString(encryptedAES, Base64.NO_WRAP);
    }

    public String getDencryptedAES() {
        return Base64.encodeToString(decryptWithRSA(encryptedAES), Base64.NO_WRAP);
    }

}

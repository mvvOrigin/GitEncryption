package com.vitaliy.encryption.encryption;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import com.google.gson.Gson;
import com.scottyab.aescrypt.AESCrypt;

import java.math.BigInteger;
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
    private static final byte[] IV = new byte[12];
    private static final int GCM_TAG_LENGTH = 128;
    private static final String AES_CIPHER = KeyProperties.KEY_ALGORITHM_AES + "/" +
            KeyProperties.BLOCK_MODE_GCM + "/" + KeyProperties.ENCRYPTION_PADDING_NONE;
    private final Gson gson;
    private final KeyStore keyStore;

    private static final String ALGORITHM_RSA = KeyProperties.KEY_ALGORITHM_RSA;
    private static final String ALGORITHM_AES = KeyProperties.KEY_ALGORITHM_AES;
    private static final String RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";
    private static final int RSA_KEY_LENGTH = 2048;
    private static final int AES_KEY_LENGTH = 256;

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private SecretKeySpec randomSecureKey;

    public Encryption(Gson gson, KeyStore keyStore) {
        this.gson = gson;
        this.keyStore = keyStore;
        generateAESKeyAndSaveToKeystore();
        generateRandomIV();
        byte[] en = encryptWithRSA(IV);
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
        try{
            final byte[] message = gson.toJson(data).getBytes(StandardCharsets.UTF_8);
            final Cipher cipher = Cipher.getInstance(AES_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, getAESKeyFromKeystore(), new GCMParameterSpec(GCM_TAG_LENGTH, IV));
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
            cipher.init(Cipher.DECRYPT_MODE, getAESKeyFromKeystore(), new GCMParameterSpec(GCM_TAG_LENGTH, IV));
            final byte[] mDecrypt = cipher.doFinal(base64EncryptedMessage);
            return new String(mDecrypt, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }

    private void generateRandomIV() {
        new Random().nextBytes(IV);
    }

    private static byte[] encryptedAES = new byte[0];

    public String encryptTouchData(String data) {
        try {
            randomSecureKey = getRandomSecureKey();
            byte[] encrypted = AESCrypt.encrypt(randomSecureKey, IV, data.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeToString(encrypted, Base64.NO_WRAP);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String decryptTouchData(String data) {
        try {
            byte[] bytes = Base64.decode(data, Base64.NO_WRAP);
            SecretKeySpec key = new SecretKeySpec(decriptAESWithRSA(), 0, 12, ALGORITHM_AES);
            byte[] decrypted = AESCrypt.decrypt(key, IV, bytes);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    private SecretKeySpec getRandomSecureKey() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM_AES);
            generator.init(AES_KEY_LENGTH);
            byte[] random  = generator.generateKey().getEncoded();
            encryptedAES = encryptWithRSA(random);
            return new SecretKeySpec(random, 0, 12, ALGORITHM_AES);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String getEncryptedAES(){
        return new String(encryptedAES);
    }

    public String getDecryptedAES(){
        byte[] key = decriptAESWithRSA();
        return Base64.encodeToString(key, Base64.NO_WRAP);
    }

    private byte[] encryptWithRSA(byte[] key) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM_RSA);
            generator.initialize(RSA_KEY_LENGTH);
            KeyPair pair = generator.generateKeyPair();
            publicKey = pair.getPublic();
            privateKey = pair.getPrivate();
            Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(key);
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] decriptAESWithRSA() {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedAES);
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }
}

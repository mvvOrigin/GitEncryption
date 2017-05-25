package com.vitaliy.encryption.encryption;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import com.google.gson.Gson;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.security.auth.x500.X500Principal;

import static com.vitaliy.encryption.injection.module.EncryptionModule.KEYSTORE_PROVIDER;

/**
 * Created by vitaliy on 25.05.17.
 */

public class EncryptionImpl implements Encryption {
    private static final String AES_KEY_ALIAS = "AES_KEY_ALIAS";
    private static final byte[] IV = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private static final int GCM_TAG_LENGTH = 128;
    private static final String AES_CIPHER = KeyProperties.KEY_ALGORITHM_AES + "/" +
            KeyProperties.BLOCK_MODE_GCM + "/" + KeyProperties.ENCRYPTION_PADDING_NONE;
    private final Gson gson;
    private final KeyStore keyStore;

    public EncryptionImpl(Gson gson, KeyStore keyStore) {
        this.gson = gson;
        this.keyStore = keyStore;
        generateAESKeyAndSaveToKeystore();
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

    @Override
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

    @Override
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
}

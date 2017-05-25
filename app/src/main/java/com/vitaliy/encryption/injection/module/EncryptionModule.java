package com.vitaliy.encryption.injection.module;

import com.google.gson.Gson;
import com.vitaliy.encryption.encryption.Encryption;
import com.vitaliy.encryption.encryption.EncryptionImpl;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.inject.Singleton;

import dagger.Module;
import dagger.Provides;

/**
 * Created by vitaliy on 25.05.17.
 */

@Module
public class EncryptionModule {

    public static final String KEYSTORE_PROVIDER = "AndroidKeyStore";

    @Singleton
    @Provides
    KeyStore providesKeyStore() {
        try {
            final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
            return keyStore;
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Singleton
    @Provides
    Encryption providesEncryption(Gson gson, KeyStore keyStore) {
        return new EncryptionImpl(gson, keyStore);
    }
}

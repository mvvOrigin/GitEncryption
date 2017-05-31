package com.vitaliy.encryption.ui;

import com.vitaliy.data.TouchData;
import com.vitaliy.encryption.core.EncryptionApplication;
import com.vitaliy.encryption.encryption.Encryption;

import javax.inject.Inject;

/**
 * Created by vitaliy on 31.05.17.
 */

public class TouchDataPresenter implements RepositoryContract.TouchPresenter {
    @Inject
    Encryption encryption;
    private RepositoryContract.View view;

    public TouchDataPresenter(RepositoryContract.View view) {
        EncryptionApplication.getAppComponent().inject(this);
        this.view = view;
    }

    @Override
    public void sendTouchData(TouchData data) {
        view.showMessage("Loading");
        view.setProgressVisible(true);

        final String encryptedMsg = encryption.encryptTouchData(data);
        final String decryptedMsg = encryption.decryptTouchData(encryptedMsg);

        final StringBuilder b = new StringBuilder();
        b.append("Decrypted:");
        b.append("\n");
        b.append("AES: ");
        b.append(encryption.getDencryptedAES());
        b.append("\n");
        b.append("\n");
        b.append("MSG: ");
        b.append("\n");
        b.append(decryptedMsg);
        b.append("\n");
        b.append("\n");
        b.append("Encrypted:");
        b.append("\n");
        b.append("AES: ");
        b.append(encryption.getEncryptedAES());
        b.append("\n");
        b.append("\n");
        b.append("MSG: ");
        b.append("\n");
        b.append(encryptedMsg);

        view.setProgressVisible(false);
        view.showMessage(b.toString());
    }
}

package com.vitaliy.encryption.ui;

import com.vitaliy.encryption.core.EncryptionApplication;
import com.vitaliy.encryption.database.DBManager;
import com.vitaliy.encryption.encryption.Encryption;
import com.vitaliy.encryption.rest.GitApi;

import java.io.IOException;
import javax.inject.Inject;

import okhttp3.ResponseBody;
import rx.android.schedulers.AndroidSchedulers;
import rx.functions.Action1;
import rx.schedulers.Schedulers;

/**
 * Created by vitaliy on 25.05.17.
 */

public class RepositoryGitPresenter implements RepositoryContract.GitPresenter {
    @Inject
    GitApi gitApi;
    @Inject
    Encryption encryption;
    @Inject
    DBManager dbManager;
    private final RepositoryContract.View view;

    public RepositoryGitPresenter(RepositoryContract.View view) {
        this.view = view;
        EncryptionApplication.getAppComponent().inject(this);
    }

    @Override
    public void getRepositories() {
        view.showMessage("Loading");
        view.setProgressVisible(true);
        gitApi.getUserRepositories()
                .subscribeOn(Schedulers.io())
                .observeOn(AndroidSchedulers.mainThread())
                .subscribe(new Action1<ResponseBody>() {
                    @Override
                    public void call(ResponseBody responseBody) {
                        if (responseBody != null) {
                            encryptAndSave(getStringResponseBody(responseBody));
                            view.showMessage(getAndDecrypt());
                            view.setProgressVisible(false);
                        }
                    }
                }, new Action1<Throwable>() {
                    @Override
                    public void call(Throwable throwable) {
                        if (throwable != null) {
                            throwable.printStackTrace();
                            view.showMessage(throwable.toString());
                            view.setProgressVisible(false);
                        }
                    }
                });
    }

    private void encryptAndSave(String message) {
        final String encrypted = encryption.encrypt(message);
        dbManager.saveMessage(encrypted);
        view.showMessage(encrypted);
    }

    private String getAndDecrypt() {
        final String encrypted = dbManager.getMessage();
        return encryption.decrypt(encrypted);
    }

    private String getStringResponseBody(ResponseBody responseBody) {
        try {
            return responseBody.string();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}

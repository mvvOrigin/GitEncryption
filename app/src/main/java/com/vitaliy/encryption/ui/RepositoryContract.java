package com.vitaliy.encryption.ui;

/**
 * Created by vitaliy on 25.05.17.
 */

public interface RepositoryContract {

    interface View {
        void showMessage(String string);
        void setProgressVisible(boolean enabled);
    }

    interface Presenter {
        void getRepositories();
    }
}

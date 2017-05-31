package com.vitaliy.encryption.ui;

import com.vitaliy.data.TouchData;

/**
 * Created by vitaliy on 25.05.17.
 */

public interface RepositoryContract {

    interface View {
        void showMessage(String string);
        void setProgressVisible(boolean enabled);
    }

    interface GitPresenter {
        void getRepositories();
    }

    interface TouchPresenter {
        void sendTouchData(TouchData data);
    }
}

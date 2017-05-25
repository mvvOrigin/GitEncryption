package com.vitaliy.encryption.core;

import android.app.Application;

import com.vitaliy.encryption.injection.component.AppComponent;
import com.vitaliy.encryption.injection.component.DaggerAppComponent;
import com.vitaliy.encryption.injection.module.ApplicationModule;

/**
 * Created by vitaliy on 25.05.17.
 */

public class EncryptionApplication extends Application {

    private static AppComponent appComponent;

    @Override
    public void onCreate() {
        super.onCreate();
        appComponent = DaggerAppComponent.builder()
                .applicationModule(new ApplicationModule(this))
                .build();
    }

    public static AppComponent getAppComponent() {
        return appComponent;
    }
}

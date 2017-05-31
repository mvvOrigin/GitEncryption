package com.vitaliy.encryption.injection.component;

import com.vitaliy.encryption.ui.RepositoryGitPresenter;
import com.vitaliy.encryption.injection.module.ApplicationModule;
import com.vitaliy.encryption.injection.module.DatabaseModule;
import com.vitaliy.encryption.injection.module.EncryptionModule;
import com.vitaliy.encryption.injection.module.GitApiModule;
import com.vitaliy.encryption.ui.TouchDataPresenter;

import javax.inject.Singleton;

import dagger.Component;

/**
 * Created by vitaliy on 25.05.17.
 */

@Singleton
@Component(modules = {ApplicationModule.class, GitApiModule.class, EncryptionModule.class, DatabaseModule.class})
public interface AppComponent {
    void inject(RepositoryGitPresenter presenter);
    void inject(TouchDataPresenter presenter);
}

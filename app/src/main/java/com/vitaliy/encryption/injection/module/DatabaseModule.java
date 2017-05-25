package com.vitaliy.encryption.injection.module;

import android.content.Context;

import com.vitaliy.encryption.database.DBHelper;
import com.vitaliy.encryption.database.DBManager;

import javax.inject.Singleton;

import dagger.Module;
import dagger.Provides;

/**
 * Created by vitaliy on 25.05.17.
 */

@Module
public class DatabaseModule {

    @Singleton
    @Provides
    DBHelper providesDBHelper(Context context) {
        return new DBHelper(context);
    }

    @Singleton
    @Provides
    DBManager providesDBManager(DBHelper dbHelper) {
        return new DBManager(dbHelper);
    }
}

package com.vitaliy.encryption.database;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

/**
 * Created by vitaliy on 25.05.17.
 */

public class DBHelper extends SQLiteOpenHelper {
    private static final String DATABASE_NAME = "repos.db";
    private static final int DATABASE_VERSION = 1;

    static final String TABLE_NAME = "repository";
    static final String ID = "id";
    static final String MESSAGE = "message";

    public DBHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("create table "
                + TABLE_NAME + " ("
                + ID + " integer primary key,"
                + MESSAGE + " text);");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {

    }
}

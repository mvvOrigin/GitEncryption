package com.vitaliy.encryption.database;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

/**
 * Created by vitaliy on 25.05.17.
 */

import static com.vitaliy.encryption.database.DBHelper.*;

@SuppressWarnings("WeakerAccess")
public class DBManager {
    private final SQLiteDatabase sqLiteDatabase;

    public DBManager(DBHelper dbHelper) {
        this.sqLiteDatabase = dbHelper.getWritableDatabase();
    }

    public void saveMessage(String message) {
        sqLiteDatabase.insertWithOnConflict(TABLE_NAME, null, fromMessage(message), SQLiteDatabase.CONFLICT_REPLACE);
    }

    public String getMessage() {
        return fromCursor(sqLiteDatabase.query(TABLE_NAME, null, null, null, null, null, null));
    }

    public ContentValues fromMessage(String message) {
        final ContentValues values = new ContentValues();
        values.put(ID, 1);
        values.put(MESSAGE, message);
        return values;
    }

    public String fromCursor(Cursor cursor) {
        if (cursor != null && cursor.moveToFirst()) {
            return cursor.getString(cursor.getColumnIndex(MESSAGE));
        } else {
            return null;
        }
    }
}

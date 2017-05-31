package com.vitaliy.data;

/**
 * Created by vitaliy on 31.05.17.
 */

public class TouchData {
    private float x;
    private float y;

    public TouchData(float x, float y) {
        this.x = x;
        this.y = y;
    }

    public float getX() {
        return x;
    }

    public void setX(float x) {
        this.x = x;
    }

    public float getY() {
        return y;
    }

    public void setY(float y) {
        this.y = y;
    }

    @Override
    public String toString() {
        return "TouchData{" +
                "y=" + y +
                ", x=" + x +
                '}';
    }
}

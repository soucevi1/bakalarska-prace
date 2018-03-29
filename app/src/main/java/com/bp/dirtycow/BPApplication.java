package com.bp.dirtycow;

import android.app.Application;

// Zdroj: http://www.gadgetsaint.com/android/no-internet-connectivity-android/#.Wq_kX9Yo_iE

public class BPApplication extends Application {

    private static BPApplication mInstance;

    @Override
    public void onCreate() {
        super.onCreate();

        mInstance = this;
    }

    public static synchronized BPApplication getInstance() {
        return mInstance;
    }

    public void setConnectionListener(ConnectionReceiver.ConnectionReceiverListener listener) {
        ConnectionReceiver.connectionReceiverListener = listener;
    }
}

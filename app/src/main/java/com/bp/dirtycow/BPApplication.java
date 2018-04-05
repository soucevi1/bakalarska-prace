// Zdroj: Clanek Handle No Internet Connectivity in Android Activity, autor Anu S Pillai
//        (http://www.gadgetsaint.com/android/no-internet-connectivity-android/#.Wq_kX9Yo_iE)
// Jde pouze o pomocnou tridu, ktera slouzi pro spravnou funkcnost tridy ConnectionReceiver
package com.bp.dirtycow;

import android.app.Application;

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

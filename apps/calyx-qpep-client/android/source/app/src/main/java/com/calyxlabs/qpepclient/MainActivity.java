/* OpenQPEP v1.0.0-rc (Release Candidate 1.0.0) */
package com.calyxlabs.qpepclient;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;

public class MainActivity extends Activity {
    private static final int IMMERSIVE_FLAGS = 0x00001706;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().getDecorView().setSystemUiVisibility(IMMERSIVE_FLAGS);
        WebView wv = new WebView(this);
        WebSettings ws = wv.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setDatabaseEnabled(true);
        wv.loadUrl("file:///android_asset/calyx_qpep_app.html");
        setContentView(wv);
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        getWindow().getDecorView().setSystemUiVisibility(IMMERSIVE_FLAGS);
    }

    /* OpenQPEP v1.0.0-rc: Read-only native ActivityManager.MemoryInfo helper for >= 12 GB RAM gate */
    private double getDeviceRamGiB() {
        android.app.ActivityManager am = (android.app.ActivityManager) getSystemService(android.content.Context.ACTIVITY_SERVICE);
        if (am == null) return 0.0;
        android.app.ActivityManager.MemoryInfo mi = new android.app.ActivityManager.MemoryInfo();
        am.getMemoryInfo(mi);
        return mi.totalMem / (1024.0 * 1024.0 * 1024.0);
    }
}

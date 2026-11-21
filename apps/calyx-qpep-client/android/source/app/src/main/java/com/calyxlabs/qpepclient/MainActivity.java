/* OpenQPEP v1.1.7-pc (Production Candidate 1.1.7) */
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
}

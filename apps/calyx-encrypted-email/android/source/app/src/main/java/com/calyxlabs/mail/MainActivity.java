/* OpenQPEP Official Release 1.1.0 (OpenQPEP/1.1.0) */
package com.calyxlabs.mail;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.view.Window;
import android.view.WindowInsetsController;
import android.view.WindowManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;

public class MainActivity extends Activity implements Runnable {
    private WebView wv;
    private String lastUrl = "";
    private String pendingTarget = "";
    private String pendingData = "";

    private final class CalyxHardwareBridge {
        @JavascriptInterface
        public double getDeviceRamGiB() {
            return MainActivity.this.getDeviceRamGiB();
        }
    }

    private static String sanitizeFilename(String rawName) {
        if (rawName == null) return "calyxmail_export.bin";
        String base = new File(rawName).getName().replaceAll("[\\\\/:*?\"<>|]", "_").trim();
        return base.isEmpty() ? "calyxmail_export.bin" : base;
    }

    private void hideSystemBars() {
        Window w = getWindow();
        if (w == null) return;
        w.addFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN);
        WindowManager.LayoutParams lp = w.getAttributes();
        if (lp != null) {
            lp.layoutInDisplayCutoutMode = WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES;
            w.setAttributes(lp);
        }
        View decor = w.getDecorView();
        if (decor == null) return;
        decor.setSystemUiVisibility(0x1706);
        if (Build.VERSION.SDK_INT >= 30) {
            WindowInsetsController ic = decor.getWindowInsetsController();
            if (ic != null) {
                ic.setSystemBarsBehavior(WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE);
                ic.hide(7);
            }
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        hideSystemBars();
        wv = new WebView(this);
        WebSettings ws = wv.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setAllowFileAccess(true);
        ws.setAllowContentAccess(false);
        wv.clearCache(true);
        ws.setMediaPlaybackRequiresUserGesture(false);
        ws.setCacheMode(WebSettings.LOAD_NO_CACHE);
        wv.setWebChromeClient(new CalyxChromeClient());
        wv.addJavascriptInterface(new CalyxHardwareBridge(), "CalyxHardwareBridge");
        wv.setSystemUiVisibility(0x1706);
        setContentView(wv);
        hideSystemBars();
        wv.loadUrl("file:///android_asset/calyx_mail.html");
        wv.postOnAnimation(this);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        hideSystemBars();
        if (wv != null) {
            wv.loadUrl("javascript:window.__onAndroidCameraPermissionReady()");
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        hideSystemBars();
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        hideSystemBars();
    }

    @Override
    public void run() {
        if (wv == null) return;
        wv.setSystemUiVisibility(0x1706);
        wv.postOnAnimation(this);
        String url = wv.getUrl();
        if (url == null || url.equals(lastUrl)) return;
        if (url.indexOf("#CALYX_CAM|") >= 0) {
            lastUrl = url;
            if (checkSelfPermission("android.permission.CAMERA") != 0) {
                requestPermissions(new String[]{"android.permission.CAMERA"}, 1003);
            } else {
                wv.loadUrl("javascript:window.__onAndroidCameraPermissionReady()");
            }
            return;
        }
        if (url.indexOf("#CALYX_OPEN|") >= 0) {
            lastUrl = url;
            int idx = url.lastIndexOf("|");
            if (idx < 0) return;
            pendingTarget = url.substring(idx + 1);
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            startActivityForResult(i, 1001);
            return;
        }
        if (url.indexOf("#CALYX_SAVE|") >= 0) {
            lastUrl = url;
            int idx = url.lastIndexOf("|");
            if (idx < 0) return;
            pendingData = url.substring(idx + 1);
            String head = url.substring(0, idx);
            int idx2 = head.lastIndexOf("|");
            if (idx2 < 0) return;
            String fname = sanitizeFilename(head.substring(idx2 + 1));
            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            i.putExtra(Intent.EXTRA_TITLE, fname);
            startActivityForResult(i, 1002);
        }
    }

    @Override
    protected void onActivityResult(int reqCode, int resCode, Intent data) {
        super.onActivityResult(reqCode, resCode, data);
        hideSystemBars();
        if (wv != null) wv.postOnAnimation(this);
        if (resCode != RESULT_OK || data == null) return;
        Uri uri = data.getData();
        if (uri == null) return;
        try {
            if (reqCode == 1001) {
                ContentResolver cr = getContentResolver();
                InputStream is = cr.openInputStream(uri);
                if (is == null) return;
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int n;
                while ((n = is.read(buf)) >= 0) baos.write(buf, 0, n);
                is.close();
                String b64Data = Base64.encodeToString(baos.toByteArray(), Base64.NO_WRAP);
                String b64Uri = Base64.encodeToString(uri.toString().getBytes(), Base64.NO_WRAP);
                wv.loadUrl("javascript:window.__onAndroidFileOpened('" + pendingTarget + "','" + b64Uri + "','" + b64Data + "')");
            } else if (reqCode == 1002) {
                byte[] raw = Base64.decode(pendingData, Base64.DEFAULT);
                ContentResolver cr = getContentResolver();
                OutputStream os = cr.openOutputStream(uri);
                if (os == null) return;
                os.write(raw);
                os.flush();
                os.close();
                String b64Uri = Base64.encodeToString(uri.toString().getBytes(), Base64.NO_WRAP);
                wv.loadUrl("javascript:window.__onAndroidFileSaved('" + b64Uri + "')");
            }
        } catch (Exception ignored) {}
    }

    /* OpenQPEP Official Release 1.0.0: Read-only native ActivityManager.MemoryInfo helper for >= 12 GB RAM gate */
    private double getDeviceRamGiB() {
        android.app.ActivityManager am = (android.app.ActivityManager) getSystemService(android.content.Context.ACTIVITY_SERVICE);
        if (am == null) return 0.0;
        android.app.ActivityManager.MemoryInfo mi = new android.app.ActivityManager.MemoryInfo();
        am.getMemoryInfo(mi);
        return mi.totalMem / (1024.0 * 1024.0 * 1024.0);
    }
}

/* OpenQPEP Official Release 1.0.0 (OpenQPEP/1.0.0) */
package com.calyxlabs.mail;

import android.webkit.PermissionRequest;
import android.webkit.WebChromeClient;

public class CalyxChromeClient extends WebChromeClient {
    @Override
    public void onPermissionRequest(PermissionRequest request) {
        if (request != null) {
            request.grant(request.getResources());
        }
    }
}

/* OpenQPEP v1.1.7-pc (Production Candidate 1.1.7) */
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

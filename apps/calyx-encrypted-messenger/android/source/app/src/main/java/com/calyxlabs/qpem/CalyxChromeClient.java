/* OpenQPEP v1.1.0-pc (Production Candidate 1.1.0) */
package com.calyxlabs.qpem;

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

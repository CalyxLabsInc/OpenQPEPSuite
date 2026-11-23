/* OpenQPEP Official Release 1.1.0 (OpenQPEP/1.1.0) */
package com.calyxlabs.mail;

import android.net.Uri;
import android.webkit.PermissionRequest;
import android.webkit.WebChromeClient;
import java.util.ArrayList;
import java.util.List;

public class CalyxChromeClient extends WebChromeClient {
    @Override
    public void onPermissionRequest(PermissionRequest request) {
        if (request == null) return;
        Uri origin = request.getOrigin();
        boolean trustedOrigin = (origin == null) || "file".equalsIgnoreCase(origin.getScheme())
                || ("https".equalsIgnoreCase(origin.getScheme()) && origin.getHost() != null
                    && (origin.getHost().equalsIgnoreCase("mail.calyxlabsinc.org") || origin.getHost().equalsIgnoreCase("calyxmail.org")));
        if (!trustedOrigin) {
            request.deny();
            return;
        }
        List<String> allowed = new ArrayList<>();
        for (String res : request.getResources()) {
            if (PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(res)) {
                allowed.add(res);
            }
        }
        if (!allowed.isEmpty()) {
            request.grant(allowed.toArray(new String[0]));
        } else {
            request.deny();
        }
    }
}

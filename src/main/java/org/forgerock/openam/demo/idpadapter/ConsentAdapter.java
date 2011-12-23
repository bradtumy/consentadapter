/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2011 ForgeRock AS. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 */
package org.forgerock.openam.demo.idpadapter;

import com.iplanet.am.util.SystemProperties;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.saml2.assertion.Issuer;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.plugins.SAML2IdentityProviderAdapter;
import com.sun.identity.saml2.protocol.AuthnRequest;
import com.sun.identity.shared.Constants;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.encode.Base64;
import java.util.Set;
import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 * @author Peter Major
 */
public class ConsentAdapter implements SAML2IdentityProviderAdapter {

    private static Debug debug = Debug.getInstance("ConsentAdapter");

    public boolean preSendResponse(AuthnRequest authnRequest,
            String hostProviderID,
            String realm,
            HttpServletRequest request,
            HttpServletResponse response,
            Object session,
            String reqID,
            String relayState) throws SAML2Exception {
        Issuer issuer = authnRequest.getIssuer();
        String issuerName = issuer.getValue();
        SSOToken token = (SSOToken) session;
        try {
            AMIdentity identity = IdUtils.getIdentity(token);
            Set<String> consent = identity.getAttribute("givenName");
            if (consent != null && consent.contains(issuerName)) {
                //The issuer is already in the user attribute, so the user must
                //have accepted the consent already
                return false;
            } else {
                //User did not accept the consent yet
                request.setAttribute("realm", realm);
                request.setAttribute("ssoToken", token);
                request.setAttribute("reqID", reqID);
                request.setAttribute("relayState", relayState);
                request.setAttribute("idpEntityID", hostProviderID);
                request.setAttribute("spEntityID", issuerName);
                String query = request.getQueryString();
                String gotoURL = request.getRequestURI() + "?";
                int idx = query.indexOf(SystemProperties.get(Constants.AM_COOKIE_NAME) + "=");
                if (idx != -1) {
                    //if the session id is in the queryparams let's get rid of it
                    int idx2 = query.indexOf('&', idx);
                    if (idx2 == -1) {
                        gotoURL += query.substring(0, idx - 1);
                    } else {
                        gotoURL += query.substring(0, idx - 1) + query.substring(idx2);
                    }
                } else {
                    gotoURL += query;
                }
                request.setAttribute("gotoURL", Base64.encode(gotoURL.getBytes("UTF-8")));
                RequestDispatcher rd = request.getRequestDispatcher("/consent.jsp");
                rd.forward(request, response);

                return true;
            }
        } catch (Exception ex) {
            debug.error("Error while retrieving Identity", ex);
            //let's ignore this for now
        }
        return false;
    }
}

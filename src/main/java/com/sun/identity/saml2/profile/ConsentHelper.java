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
package com.sun.identity.saml2.profile;

import com.sun.identity.saml2.assertion.Attribute;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.plugins.IDPAttributeMapper;
import java.util.List;
import javax.servlet.http.HttpServletRequest;

/**
 *
 * @author Peter Major
 */
public class ConsentHelper {

    public static List<Attribute> getAttributes(HttpServletRequest request) throws SAML2Exception {
        String realm = (String) request.getAttribute("realm");
        String idpEntityID = (String) request.getAttribute("idpEntityID");
        String spEntityID = (String) request.getAttribute("spEntityID");
        Object token = request.getAttribute("ssoToken");
        IDPAttributeMapper mapper = IDPSSOUtil.getIDPAttributeMapper(realm, idpEntityID);
        return mapper.getAttributes(token, idpEntityID, spEntityID, realm);
    }
}

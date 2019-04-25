package org.apache.kafka.common.security.saml;

import dstsauthentication.Claim;
import system.DateTime;
import system.collections.IList;


import java.util.ArrayList;
import java.util.List;

public class Token {
    public List<org.apache.kafka.common.security.saml.Claim> Claims;
    public String ValidFrom;
    public String ValidTo;

    public Token(Claim[] claims, String from, String to){
        ValidFrom = from;
        ValidTo = to;
        Claims = new ArrayList<>();
        for (Claim claim: claims
             ) {
            Claims.add(new org.apache.kafka.common.security.saml.Claim(claim.getClaimType(),
                    claim.getIssuer(),
                    claim.getOriginalIssuer(),
                    claim.getLabel(),
                    claim.getNameClaimType(),
                    claim.getRoleClaimType(),
                    claim.getValue(),
                    claim.getValueType()));
        }
    }
}

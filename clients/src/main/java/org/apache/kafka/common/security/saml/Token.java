package org.apache.kafka.common.security.saml;

import dstsauthentication.Claim;
import system.DateTime;

import java.util.List;

public class Token {
    public Claim[] Claims;
    public DateTime ValidFrom;
    public DateTime ValidTo;

    public Token(Claim[] claims, DateTime from, DateTime to){
        ValidFrom = from;
        ValidTo = to;
        Claims = claims;
    }
}

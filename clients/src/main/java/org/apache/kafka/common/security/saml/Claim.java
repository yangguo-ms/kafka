package org.apache.kafka.common.security.saml;

public class Claim {
    public String ClaimType;
    public String Issuer;
    public String OriginalIssuer;
    public String Label;
    public String NameClaimType;
    public String RoleClaimType;
    public String Value;
    public String ValueType;

    public Claim(String claimType,
                 String issuer,
                 String originalIssuer,
                 String label,
                 String nameClaimType,
                 String roleClaimType,
                 String value,
                 String valueType){
        ClaimType = claimType;
        Issuer =issuer;
        OriginalIssuer = originalIssuer;
        Label = label;
        NameClaimType = nameClaimType;
        RoleClaimType = roleClaimType;
        Value = value;
        ValueType = valueType;
    }
}

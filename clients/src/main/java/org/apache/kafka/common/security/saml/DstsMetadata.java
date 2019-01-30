package org.apache.kafka.common.security.saml;

public class DstsMetadata {
    public String DstsDns;
    public String ServiceDnsName;
    public String ServiceName;
    public String DstsRealm;
    public String DstsClaimRole;

    public DstsMetadata(String dstsDns, String serviceDnsName, String serviceName, String dstsRealm, String claimRole){
        DstsDns = dstsDns;
        ServiceDnsName = serviceDnsName;
        ServiceName = serviceName;
        DstsRealm = dstsRealm;
        DstsClaimRole = claimRole;
    }
}

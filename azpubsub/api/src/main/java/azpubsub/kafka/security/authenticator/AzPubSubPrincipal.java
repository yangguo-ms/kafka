package azpubsub.kafka.security.authenticator;

public class AzPubSubPrincipal {
    public String principalType;
    public String principalName;

    public AzPubSubPrincipal(String type, String name) {
        principalName = name;
        principalType = type;
    }

    public String getPrincipalType() {
        return principalType;
    }

    public String getPrincipalName() {
        return principalName;
    }
}

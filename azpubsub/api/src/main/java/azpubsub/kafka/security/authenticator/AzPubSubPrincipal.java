package azpubsub.kafka.security.authenticator;

/**
 * AzPubSubPrincipal class.
 */
public class AzPubSubPrincipal {
    private String principalType;
    private String principalName;

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

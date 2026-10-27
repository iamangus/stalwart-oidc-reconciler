package dev.srvd.mail;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public final class MailResourceFactory implements RealmResourceProviderFactory {
    public RealmResourceProvider create(KeycloakSession session) {
        return new RealmResourceProvider() {
            public Object getResource() { return new MailResource(session); }
            public void close() {}
        };
    }
    public String getId() { return "srvd-mail"; }
    public void init(Config.Scope config) {}
    public void postInit(KeycloakSessionFactory factory) {}
    public void close() {}
}

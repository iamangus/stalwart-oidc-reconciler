package dev.srvd.mail;

import jakarta.ws.rs.core.MultivaluedMap;
import org.keycloak.authentication.*;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.events.Errors;
import org.keycloak.models.*;
import org.keycloak.services.messages.Messages;

public final class MailPasswordFactory extends UsernamePasswordFormFactory {
    public String getId() { return "srvd-mail-password"; }
    public String getDisplayType() { return "SRVD username, recovery email or mailbox"; }
    public Authenticator create(KeycloakSession session) {
        return new UsernamePasswordForm(session) {
            protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> data) {
                if (context.getUser() == null) {
                    try { data.putSingle("username", MailLogin.username(session, context.getRealm(), data.getFirst("username"))); }
                    catch (ModelDuplicateException conflict) {
                        AuthenticatorUtils.dummyHash(context);
                        context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                        context.failureChallenge(AuthenticationFlowError.INVALID_USER, challenge(context, Messages.INVALID_USER, "username"));
                        return false;
                    }
                }
                return super.validateForm(context, data);
            }
        };
    }
}

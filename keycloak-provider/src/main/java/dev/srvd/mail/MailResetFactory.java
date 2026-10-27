package dev.srvd.mail;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialChooseUser;
import org.keycloak.models.ModelDuplicateException;

/** Only changes identifier resolution. Native reset email/token/password/MFA
 * behavior remains in Keycloak's following executions. */
public final class MailResetFactory extends ResetCredentialChooseUser {
    public String getId() { return "srvd-mail-reset-user"; }
    public String getDisplayType() { return "SRVD reset user lookup"; }
    public void action(AuthenticationFlowContext context) {
        var data = context.getHttpRequest().getDecodedFormParameters();
        try { data.putSingle("username", MailLogin.username(context.getSession(), context.getRealm(), data.getFirst("username"))); }
        catch (ModelDuplicateException conflict) {
            context.clearUser();
            context.success(); // native next step emits the same generic response
            return;
        }
        super.action(context);
    }
}

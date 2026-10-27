package dev.srvd.mail;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.keycloak.models.*;

/** Exact attribute lookup, never email-prefix/name matching. Ambiguity fails
 * closed even if one of the candidates is a normal username/email match. */
final class MailLogin {
    static String username(KeycloakSession session, RealmModel realm, String input) {
        if (input == null || input.length() > 255 || !"apps".equals(realm.getName())) return input;
        String address = input.trim().toLowerCase(Locale.ROOT);
        if (!address.endsWith("@srvd.dev")) return input;
        Map<String, UserModel> matches = new LinkedHashMap<>();
        UserModel user = session.users().getUserByUsername(realm, address);
        if (user != null) matches.put(user.getId(), user);
        if (realm.isLoginWithEmailAllowed()) {
            user = session.users().getUserByEmail(realm, address);
            if (user != null) matches.put(user.getId(), user);
        }
        try (var users = session.users().searchForUserByUserAttributeStream(realm, "mail_address", address)) {
            users.limit(2).forEach(u -> {
                if (u.getServiceAccountClientLink() == null && u.getAttributeStream("mail_address").toList().equals(java.util.List.of(address)))
                    matches.put(u.getId(), u);
            });
        }
        if (matches.size() > 1) throw new ModelDuplicateException("Ambiguous login identifier");
        return matches.isEmpty() ? input : matches.values().iterator().next().getUsername();
    }
}

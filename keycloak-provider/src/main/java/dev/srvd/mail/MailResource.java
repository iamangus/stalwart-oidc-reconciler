package dev.srvd.mail;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Objects;
import org.keycloak.models.*;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;

/** Deliberately not a general user-edit API. Only the allocator's service
 * account may set an absent/identical protected mailbox claim in apps. */
@jakarta.ws.rs.ext.Provider
public final class MailResource {
    public static final String CLIENT = "stalwart-mail-publisher";
    public static final String ROLE = "srvd-mail-publish";
    private final KeycloakSession session;
    public MailResource(KeycloakSession session) { this.session = session; }
    public record AddressRequest(String address) {}

    @PUT @Path("users/{id}/address") @Consumes(MediaType.APPLICATION_JSON)
    public Response publish(@PathParam("id") String id, AddressRequest request) {
        RealmModel realm = session.getContext().getRealm();
        authorize(realm, new AppAuthManager.BearerTokenAuthenticator(session).authenticate());
        return publishAuthorized(realm, id, request);
    }

    Response publishAuthorized(RealmModel realm, String id, AddressRequest request) {
        if (request == null || request.address() == null || !request.address().matches("[a-z0-9]+(?:[.-][a-z0-9]+)*@srvd\\.dev")
                || request.address().indexOf('@') > 64) throw new BadRequestException();
        UserModel user = session.users().getUserById(realm, id);
        if (user == null || user.getServiceAccountClientLink() != null) throw new NotFoundException();
        List<String> current = user.getAttributeStream("mail_address").toList();
        if (!current.isEmpty()) {
            if (!current.equals(List.of(request.address()))) throw new ClientErrorException(Response.Status.CONFLICT);
            return Response.noContent().build();
        }
        OrganizationProvider organizations = session.getProvider(OrganizationProvider.class);
        String organizationId = realm.getAttribute("srvdMailOrganizationId");
        OrganizationModel organization = organizationId == null ? null : organizations.getById(organizationId);
        if (organization == null || !organization.isEnabled() || !organization.isMember(user)
                || !user.isEnabled() || !user.isEmailVerified() || user.getRequiredActionsStream().findAny().isPresent()
                || user.getFirstName() == null || user.getFirstName().isBlank()
                || user.getLastName() == null || user.getLastName().isBlank()) throw new ForbiddenException();
        try (var matches = session.users().searchForUserByUserAttributeStream(realm, "mail_address", request.address())) {
            if (matches.anyMatch(other -> !other.getId().equals(id))) throw new ClientErrorException(Response.Status.CONFLICT);
        }
        UserModel login = session.users().getUserByUsername(realm, request.address());
        UserModel email = session.users().getUserByEmail(realm, request.address());
        if (login != null && !login.getId().equals(id) || email != null && !email.getId().equals(id))
            throw new ClientErrorException(Response.Status.CONFLICT);
        user.setSingleAttribute("mail_address", request.address());
        return Response.noContent().build();
    }

    static void authorize(RealmModel realm, AuthResult auth) {
        if (auth == null) throw new NotAuthorizedException("Bearer");
        ClientModel client = realm.getClientByClientId(CLIENT);
        RoleModel role = realm.getRole(ROLE);
        if (!"apps".equals(realm.getName()) || client == null || role == null
                || !CLIENT.equals(auth.getToken().getIssuedFor())
                || !Objects.equals(client.getId(), auth.getUser().getServiceAccountClientLink())
                || !auth.getUser().hasRole(role) || auth.getToken().getRealmAccess() == null
                || !auth.getToken().getRealmAccess().isUserInRole(ROLE)) throw new ForbiddenException();
    }
}

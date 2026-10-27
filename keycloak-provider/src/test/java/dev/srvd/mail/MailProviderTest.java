package dev.srvd.mail;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.*;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.representations.AccessToken;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ClientErrorException;
import java.util.List;
import org.keycloak.organization.OrganizationProvider;

class MailProviderTest {
    KeycloakSession session;
    RealmModel realm;
    UserProvider users;
    UserModel user;
    @BeforeEach void setup() {
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        users = mock(UserProvider.class);
        user = mock(UserModel.class);
        when(session.users()).thenReturn(users);
        when(realm.getName()).thenReturn("apps");
        when(realm.isLoginWithEmailAllowed()).thenReturn(true);
        when(user.getId()).thenReturn("pilot-id");
        when(user.getUsername()).thenReturn("angoo");
        when(user.getAttributeStream("mail_address")).thenAnswer(i -> Stream.of("angus.turnbull@srvd.dev"));
        when(users.searchForUserByUserAttributeStream(eq(realm), eq("mail_address"), anyString())).thenAnswer(i -> Stream.empty());
    }
    @Test void mailLookupIsExactAndCaseNormalized() {
        when(users.searchForUserByUserAttributeStream(realm,"mail_address","angus.turnbull@srvd.dev")).thenAnswer(i -> Stream.of(user));
        assertEquals("angoo", MailLogin.username(session, realm," Angus.Turnbull@SRVD.DEV "));
        assertEquals("unknown@srvd.dev", MailLogin.username(session, realm,"unknown@srvd.dev"));
        assertEquals("angoo", MailLogin.username(session, realm,"angoo"));
        assertEquals("person@gmail.com", MailLogin.username(session, realm,"person@gmail.com"));
        verify(users,never()).getUserByUsername(realm,"person@gmail.com");
    }
    @Test void aliasCannotShadowAnotherUsernameOrEmail() {
        UserModel other=mock(UserModel.class); when(other.getId()).thenReturn("other");
        when(users.getUserByUsername(realm,"angus.turnbull@srvd.dev")).thenReturn(other);
        when(users.searchForUserByUserAttributeStream(realm,"mail_address","angus.turnbull@srvd.dev")).thenAnswer(i -> Stream.of(user));
        assertThrows(ModelDuplicateException.class,()->MailLogin.username(session,realm,"angus.turnbull@srvd.dev"));
    }
    @Test void noLookupInOtherRealms() {
        when(realm.getName()).thenReturn("master");
        assertEquals("angus.turnbull@srvd.dev",MailLogin.username(session,realm,"angus.turnbull@srvd.dev"));
        verifyNoInteractions(users);
    }
    @Test void duplicateAttributeOwnersAreRejected() {
        UserModel other=mock(UserModel.class); when(other.getId()).thenReturn("other");
        when(other.getAttributeStream("mail_address")).thenAnswer(i->Stream.of("angus.turnbull@srvd.dev"));
        when(users.searchForUserByUserAttributeStream(realm,"mail_address","angus.turnbull@srvd.dev")).thenAnswer(i->Stream.of(user,other));
        assertThrows(ModelDuplicateException.class,()->MailLogin.username(session,realm,"angus.turnbull@srvd.dev"));
    }
    @Test void publicationNeedsDedicatedServiceAccountAndTokenRole() {
        assertThrows(NotAuthorizedException.class,()->MailResource.authorize(realm,null));
        AuthResult auth=mock(AuthResult.class); AccessToken token=new AccessToken();
        when(auth.getToken()).thenReturn(token);when(auth.getUser()).thenReturn(user);
        ClientModel client=mock(ClientModel.class);RoleModel role=mock(RoleModel.class);
        when(realm.getClientByClientId(MailResource.CLIENT)).thenReturn(client);
        when(realm.getRole(MailResource.ROLE)).thenReturn(role);when(client.getId()).thenReturn("publisher-client-id");
        when(user.getServiceAccountClientLink()).thenReturn("publisher-client-id");
        when(user.hasRole(role)).thenReturn(true);token.issuedFor(MailResource.CLIENT);
        assertThrows(ForbiddenException.class,()->MailResource.authorize(realm,auth));
        token.setRealmAccess(new AccessToken.Access().addRole(MailResource.ROLE));
        assertDoesNotThrow(()->MailResource.authorize(realm,auth));
        token.issuedFor("stalwart-directory-reader");assertThrows(ForbiddenException.class,()->MailResource.authorize(realm,auth));
        token.issuedFor(MailResource.CLIENT);when(user.getServiceAccountClientLink()).thenReturn(null);
        assertThrows(ForbiddenException.class,()->MailResource.authorize(realm,auth));
    }

    @Test void publicationIsNarrowAndIdempotent() {
        when(users.getUserById(realm,"pilot-id")).thenReturn(user);
        MailResource resource=new MailResource(session);
        assertEquals(204,resource.publishAuthorized(realm,"pilot-id",new MailResource.AddressRequest("angus.turnbull@srvd.dev")).getStatus());
        assertThrows(ClientErrorException.class,()->resource.publishAuthorized(realm,"pilot-id",new MailResource.AddressRequest("different@srvd.dev")));
        assertThrows(BadRequestException.class,()->resource.publishAuthorized(realm,"pilot-id",new MailResource.AddressRequest("other@gmail.com")));
        verify(user,never()).setSingleAttribute(anyString(),anyString());
    }

    @Test void onlyCompletedOrganizationMembersCanReceiveNewClaims() {
        when(users.getUserById(realm,"pilot-id")).thenReturn(user);
        when(user.getAttributeStream("mail_address")).thenAnswer(i->Stream.empty());
        OrganizationProvider organizations=mock(OrganizationProvider.class);
        OrganizationModel organization=mock(OrganizationModel.class);
        when(session.getProvider(OrganizationProvider.class)).thenReturn(organizations);
        when(realm.getAttribute("srvdMailOrganizationId")).thenReturn("org");
        when(organizations.getById("org")).thenReturn(organization);
        when(organization.isEnabled()).thenReturn(true);when(organization.isMember(user)).thenReturn(true);
        when(user.isEnabled()).thenReturn(true);when(user.getFirstName()).thenReturn("Angus");when(user.getLastName()).thenReturn("Turnbull");
        when(user.getRequiredActionsStream()).thenAnswer(i->Stream.empty());
        MailResource resource=new MailResource(session);var request=new MailResource.AddressRequest("angus.turnbull@srvd.dev");
        assertThrows(ForbiddenException.class,()->resource.publishAuthorized(realm,"pilot-id",request));
        when(user.isEmailVerified()).thenReturn(true);
        assertEquals(204,resource.publishAuthorized(realm,"pilot-id",request).getStatus());
        verify(user).setSingleAttribute("mail_address",request.address());
        when(organization.isMember(user)).thenReturn(false);
        assertThrows(ForbiddenException.class,()->resource.publishAuthorized(realm,"pilot-id",request));
    }
}

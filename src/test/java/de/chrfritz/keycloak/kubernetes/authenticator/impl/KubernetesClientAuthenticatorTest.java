package de.chrfritz.keycloak.kubernetes.authenticator.impl;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator.ReplaceUnderscores;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.models.ClientModel;

import java.net.URISyntaxException;
import java.util.List;

import static de.chrfritz.keycloak.kubernetes.authenticator.impl.KubernetesClientAuthenticator.PROVIDER_ID;
import static de.chrfritz.keycloak.kubernetes.authenticator.impl.TestUtils.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.keycloak.authentication.AuthenticationFlowError.*;
import static org.keycloak.protocol.oidc.OIDCLoginProtocol.LOGIN_PROTOCOL;
import static org.keycloak.protocol.oidc.OIDCLoginProtocol.PRIVATE_KEY_JWT;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Unit test for the {@link KubernetesClientAuthenticator}.
 */
@DisplayNameGeneration(ReplaceUnderscores.class)
class KubernetesClientAuthenticatorTest {

    private static final String EXPECTED_AUD = "https://localhost:8080/auth/realms/test-realm";
    private static final String EXPECTED_ISSUER = "http://issuer";
    private static final String EXPECTED_SUBJECT = "system:serviceaccount:dummy:dummy";
    private final KubernetesClientAuthenticator authenticator = new KubernetesClientAuthenticator();

    @Test
    void test_AuthenticateClient_successfully() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, EXPECTED_AUD, -1, -1, 60);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context, never()).failure(any(), any());
        verify(context).success();
    }

    @Test
    void test_AuthenticateClient_expired() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, EXPECTED_AUD, -80, -80, -60);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).failure(eq(INVALID_CLIENT_CREDENTIALS), any(Response.class));
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_no_yet_valid() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, EXPECTED_AUD, -1, 60, 90);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).failure(eq(INVALID_CLIENT_CREDENTIALS), any(Response.class));
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_different_signing_key_but_same_kid() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, EXPECTED_AUD, -1, -1, 60, mockKey("1"));
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).failure(eq(INVALID_CLIENT_CREDENTIALS), any(Response.class));
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_missing_key_setup() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, EXPECTED_AUD, -1, -1, 60, mockKey("2"));
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).failure(eq(CLIENT_CREDENTIALS_SETUP_REQUIRED), any(Response.class));
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_client_disabled() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", false);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, EXPECTED_AUD, -1, -1, 60);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).failure(eq(CLIENT_DISABLED), isNull());
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_wrong_audience() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        String token = mockToken(EXPECTED_SUBJECT, EXPECTED_ISSUER, "", -1, -1, 60);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).failure(eq(INVALID_CLIENT_CREDENTIALS), any(Response.class));
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_unknown_client() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        String token = mockToken(EXPECTED_SUBJECT, "http://otherIssuer", EXPECTED_AUD, -1, -1, 60);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), token);


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).failure(eq(CLIENT_NOT_FOUND), isNull());
        verify(context, never()).success();
    }

    @Test
    void test_AuthenticateClient_other_client_assertation() throws URISyntaxException {
        // given
        ClientModel client = mockClient("dummy", "system:serviceaccount:dummy:dummy@http://issuer", true);
        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(List.of(client), "other", "dummy");


        // when
        authenticator.authenticateClient(context);

        // then
        verify(context).challenge(any(Response.class));
        verify(context, never()).success();
    }

    @Test
    void test_GetId() {
        assertThat(authenticator.getId()).isEqualTo(PROVIDER_ID);
    }

    @Test
    void test_GetProtocolAuthenticatorMethods() {
        assertThat(authenticator.getProtocolAuthenticatorMethods(LOGIN_PROTOCOL))
            .hasSize(1)
            .contains(PRIVATE_KEY_JWT);

        assertThat(authenticator.getProtocolAuthenticatorMethods("dummyProtocol"))
            .isEmpty();
    }
}

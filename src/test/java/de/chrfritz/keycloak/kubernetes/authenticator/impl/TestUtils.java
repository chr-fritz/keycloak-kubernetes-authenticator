package de.chrfritz.keycloak.kubernetes.authenticator.impl;

import jakarta.ws.rs.core.MultivaluedMap;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.crypto.*;
import org.keycloak.http.HttpRequest;
import org.keycloak.jose.jws.DefaultTokenManager;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.keys.PublicKeyStorageProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.mockito.Answers;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static jakarta.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED_TYPE;
import static java.util.Objects.requireNonNull;
import static org.mockito.Mockito.*;

/**
 * Some test utils to simplifies testing the authenticator.
 * <p>
 * Most of them create some mocks.
 */
public class TestUtils {

    private TestUtils() {
    }

    private static final KeyWrapper keyWrapper = mockKey("1");

    /**
     * Create a new KeyWrapper instance with the given key id and a fresh generated rsa key.
     *
     * @param kid The key id for the new key wrapper
     * @return The generated key wrapper.
     */
    static KeyWrapper mockKey(String kid) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setPrivateKey(keyPair.getPrivate());
            keyWrapper.setPublicKey(keyPair.getPublic());
            keyWrapper.setType(KeyType.RSA);
            keyWrapper.setAlgorithm(Algorithm.RS256);
            keyWrapper.setKid(kid);
            return keyWrapper;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Create a new authentication flow context for jwt assertations
     *
     * @param clients the clients stored within the realm
     * @param token   the token within the assertation request
     * @return a new client authentication flow context
     * @throws URISyntaxException should never occur
     */
    static ClientAuthenticationFlowContext mockAuthenticationFlowContext(Collection<ClientModel> clients, String token) throws URISyntaxException {
        return mockAuthenticationFlowContext(clients, OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT, token);
    }

    /**
     * Create a new authentication flow context
     *
     * @param clients               the clients stored within the realm
     * @param clientAssertationType the client assertation type {@link OAuth2Constants}
     * @param clientAssertation     the client assertation content
     * @return a new client authentication flow context
     * @throws URISyntaxException should never occur
     */
    static ClientAuthenticationFlowContext mockAuthenticationFlowContext(Collection<ClientModel> clients, String clientAssertationType, String clientAssertation) throws URISyntaxException {
        requireNonNull(clients, "clients must not be null.");

        ClientAuthenticationFlowContext context = mock(ClientAuthenticationFlowContext.class, Answers.RETURNS_DEEP_STUBS);
        lenient().when(context.getUriInfo().getBaseUri()).thenReturn(new URI("https://localhost:8080/auth/"));

        mockHttpRequest(clientAssertationType, clientAssertation, context);

        mockRealmInfo(clients, context);
        mockKeycloakSession(context);

        return context;
    }

    private static void mockHttpRequest(String clientAssertationType, String clientAssertation, ClientAuthenticationFlowContext context) {
        HttpRequest httpRequest = context.getHttpRequest();
        MultivaluedMap<String, String> parameters = httpRequest.getDecodedFormParameters();

        lenient().when(httpRequest.getHttpHeaders().getMediaType()).thenReturn(APPLICATION_FORM_URLENCODED_TYPE);
        when(parameters.getFirst(OAuth2Constants.CLIENT_ASSERTION_TYPE)).thenReturn(clientAssertationType);
        when(parameters.getFirst(OAuth2Constants.CLIENT_ASSERTION)).thenReturn(clientAssertation);
    }

    private static void mockKeycloakSession(ClientAuthenticationFlowContext context) {
        KeycloakSession session = context.getSession();

        DefaultTokenManager t = new DefaultTokenManager(session);
        lenient().when(session.tokens()).thenReturn(t);
        lenient().when(session.getProvider(any())).thenAnswer(i -> mock(i.getArgument(0, Class.class)));
        lenient().when((Object) session.getProvider(PublicKeyStorageProvider.class)).thenReturn(new TestPublicKeyStorageProvider(keyWrapper));
        lenient().when((Object) session.getProvider(ClientSignatureVerifierProvider.class, Algorithm.RS256)).thenReturn(new AsymmetricClientSignatureVerifierProvider(session, Algorithm.RS256));
    }

    private static void mockRealmInfo(Collection<ClientModel> clients, ClientAuthenticationFlowContext context) {
        lenient().when(context.getRealm().getId()).thenReturn("test-realm");
        lenient().when(context.getRealm().getName()).thenReturn("test-realm");

        Stream<ClientModel> clientStream = clients.stream()
            .peek(c -> {
                RealmModel realm = context.getRealm();
                lenient().when(c.getRealm()).thenReturn(realm);
            });
        lenient().when(context.getRealm().getClientsStream()).thenReturn(clientStream);
    }

    /**
     * Create a new client mock with the given information.
     *
     * @param clientId    the client id
     * @param description the description
     * @param enabled     should this client be enabled?
     * @return the mocked client.
     */
    static ClientModel mockClient(String clientId, String description, boolean enabled) {
        return mockClient(clientId, description, enabled, new HashMap<>());
    }

    /**
     * Create a new client mock with the given information and attributes.
     *
     * @param clientId    the client id
     * @param description the description
     * @param enabled     should this client be enabled?
     * @param attributes  client attributes
     * @return the mocked client.
     */
    static ClientModel mockClient(String clientId, String description, boolean enabled, Map<String, String> attributes) {
        ClientModel client = mock(ClientModel.class);
        lenient().when(client.getId()).thenReturn(clientId);
        lenient().when(client.getClientId()).thenReturn(clientId);
        lenient().when(client.getDescription()).thenReturn(description);
        lenient().when(client.isEnabled()).thenReturn(enabled);
        
        // Mock getAttribute method
        lenient().when(client.getAttribute(anyString())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            return attributes.get(key);
        });
        
        return client;
    }

    /**
     * Mock a jwt access token, with the default key wrapper which is also in the authentication flow context session as
     * valid key.
     *
     * @return the created token
     */
    static String mockToken(String subject, String issuer, String aud, int diffIat, int diffNbf, int diffExp) {
        return mockToken(subject, issuer, aud, diffIat, diffNbf, diffExp, keyWrapper);
    }

    /**
     * Mock a jwt access token, with a custom key wrapper.
     *
     * @return the created token
     */
    static String mockToken(String subject, String issuer, String aud, int diffIat, int diffNbf, int diffExp, KeyWrapper keyWrapper) {
        long epochSecond = Instant.now().getEpochSecond();
        HashMap<Object, Object> map = new HashMap<>();
        map.put("sub", subject);
        map.put("iat", epochSecond + diffIat);
        map.put("exp", epochSecond + diffExp);
        map.put("nbf", epochSecond + diffNbf);
        map.put("iss", issuer);
        map.put("aud", aud);

        return new JWSBuilder().type("JWT")
            .kid(keyWrapper.getKid())
            .jsonContent(map)
            .sign(new AsymmetricSignatureSignerContext(keyWrapper));
    }
}

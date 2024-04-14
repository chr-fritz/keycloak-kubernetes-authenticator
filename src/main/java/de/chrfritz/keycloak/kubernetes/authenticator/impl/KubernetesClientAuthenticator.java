package de.chrfritz.keycloak.kubernetes.authenticator.impl;

import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.authenticators.client.AbstractClientAuthenticator;
import org.keycloak.authentication.authenticators.client.ClientAuthUtil;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.keys.loader.PublicKeyStorageManager;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;
import org.keycloak.protocol.oidc.grants.ciba.CibaGrantType;
import org.keycloak.protocol.oidc.par.endpoints.ParEndpoint;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.Urls;

import java.security.PublicKey;
import java.util.*;

import static jakarta.ws.rs.core.Response.Status.BAD_REQUEST;
import static org.keycloak.OAuthErrorException.INVALID_CLIENT;
import static org.keycloak.authentication.AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED;

/**
 * {@link org.keycloak.authentication.ClientAuthenticator} that authenticates clients by tokens that were issued for
 * kubernetes service accounts.
 * <p>
 * The kubernetes api server issues jwt token for service accounts. These token can be used either to authenticate the
 * pods using this service account to access the kubernetes api token or other services which are specified in the
 * audience.
 * <p>
 * Configuring the specific audience for this keycloak instance it is possible to use the kubernetes service account
 * token to authenticate pods as keycloak clients.
 * <p>
 * The way how this client authenticator expects the incoming request is described in <a
 * href="https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2">RFC 7523, Section 2.2. Using JWTs for Client
 * Authentication</a>.
 *
 * @see <a
 * href="https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#serviceaccount-token-volume-projection">ServiceAccount
 * token volume projection</a>
 * @see <a href="https://www.rfc-editor.org/info/rfc7523">RFC 7523: JSON Web Token (JWT) Profile for OAuth 2.0 Client
 * Authentication and Authorization Grants</a>
 */
public class KubernetesClientAuthenticator extends AbstractClientAuthenticator {
    public static final String PROVIDER_ID = "kubernetes-jwt";

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        ExtendedJwtClientValidator validator = new ExtendedJwtClientValidator(context);
        if (!validator.clientAssertionParametersValidation()) {
            return;
        }

        try {
            validator.readJws();
            if (!validator.validateClient()) {
                return;
            }
            if (!validator.validateSignatureAlgorithm()) {
                return;
            }

            RealmModel realm = validator.getRealm();
            ClientModel client = validator.getClient();
            JWSInput jws = validator.getJws();
            JsonWebToken token = validator.getToken();
            String clientAssertion = validator.getClientAssertion();

            // Get client key and validate signature
            PublicKey clientPublicKey = getSignatureValidationKey(client, context, jws);
            if (clientPublicKey == null) {
                // Error response already set to context
                return;
            }

            if (!isTokenSignatureValid(context, clientAssertion, client)) {
                throw new TokenValidationException("Signature on JWT token failed validation");
            }

            // Allow both "issuer" or "token-endpoint" as audience
            List<String> expectedAudiences = getExpectedAudiences(context, realm);
            if (!token.hasAnyAudience(expectedAudiences)) {
                throw new TokenValidationException(
                    "Token audience doesn't match domain. Expected audiences are any of " + expectedAudiences
                        + " but audience from token is '" + Arrays.asList(token.getAudience()) + "'"
                );
            }

            validator.validateToken();
            validator.validateTokenReuse();

            context.success();
        } catch (Exception e) {
            ServicesLogger.LOGGER.errorValidatingAssertion(e);

            Response challengeResponse = ClientAuthUtil.errorResponse(
                BAD_REQUEST.getStatusCode(),
                INVALID_CLIENT,
                "Client authentication with signed JWT failed: " + e.getMessage()
            );
            context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, challengeResponse);
        }
    }

    /**
     * Check that the token signature is valid against the found client.
     *
     * @param context         The context of the current client authentication flow.
     * @param clientAssertion The actual jwt token which were sent within the client assertation parameter.
     * @param client          The found client model.
     * @return true if the signature is valid, false otherwise.
     */
    private static boolean isTokenSignatureValid(ClientAuthenticationFlowContext context, String clientAssertion, ClientModel client) {
        try {
            JsonWebToken jwt = context.getSession()
                .tokens()
                .decodeClientJWT(clientAssertion, client, JsonWebToken.class);
            return jwt != null;
        } catch (RuntimeException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            throw new TokenValidationException("Signature on JWT token failed validation", cause);
        }
    }

    protected static PublicKey getSignatureValidationKey(ClientModel client, ClientAuthenticationFlowContext context, JWSInput jws) {
        PublicKey publicKey = PublicKeyStorageManager.getClientPublicKey(context.getSession(), client, jws);
        if (publicKey == null) {
            Response challengeResponse = ClientAuthUtil.errorResponse(BAD_REQUEST.getStatusCode(), INVALID_CLIENT, "Unable to load public key");
            context.failure(CLIENT_CREDENTIALS_SETUP_REQUIRED, challengeResponse);
            return null;
        } else {
            return publicKey;
        }
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getHelpText() {
        return "Validates client based on signed JWT issued by client and signed with the Client private key";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public List<ProviderConfigProperty> getConfigPropertiesPerClient() {
        return List.of();
    }

    @Override
    public Map<String, Object> getAdapterConfiguration(ClientModel client) {
        return new HashMap<>();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Set<String> getProtocolAuthenticatorMethods(String loginProtocol) {
        if (Objects.equals(loginProtocol, OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            Set<String> results = new HashSet<>();
            results.add(OIDCLoginProtocol.PRIVATE_KEY_JWT);
            return results;
        } else {
            return Collections.emptySet();
        }
    }

    private List<String> getExpectedAudiences(ClientAuthenticationFlowContext context, RealmModel realm) {
        String issuerUrl = Urls.realmIssuer(context.getUriInfo().getBaseUri(), realm.getName());

        String tokenUrl = OIDCLoginProtocolService.tokenUrl(context.getUriInfo().getBaseUriBuilder())
            .build(realm.getName())
            .toString();
        String parEndpointUrl = ParEndpoint.parUrl(context.getUriInfo().getBaseUriBuilder())
            .build(realm.getName())
            .toString();
        String backchannelAuthenticationUrl = CibaGrantType.authorizationUrl(context.getUriInfo().getBaseUriBuilder())
            .build(realm.getName())
            .toString();

        return List.of(issuerUrl, tokenUrl, parEndpointUrl, backchannelAuthenticationUrl);
    }

    @Override
    public String getDisplayType() {
        return "Kubernetes Service Account";
    }
}

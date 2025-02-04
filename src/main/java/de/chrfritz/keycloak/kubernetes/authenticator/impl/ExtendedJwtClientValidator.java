package de.chrfritz.keycloak.kubernetes.authenticator.impl;

import jakarta.ws.rs.core.Response;
import lombok.Getter;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.authenticators.client.ClientAuthUtil;
import org.keycloak.authentication.authenticators.client.JWTClientValidator;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.utils.StringUtil;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import static jakarta.ws.rs.core.Response.Status.BAD_REQUEST;
import static org.keycloak.authentication.AuthenticationFlowError.CLIENT_DISABLED;
import static org.keycloak.authentication.AuthenticationFlowError.CLIENT_NOT_FOUND;

/**
 * Extends the existing {@link JWTClientValidator} for validating kubernetes service account token.
 * <p>
 * It expects that the description of the expected client contains at least one line that matches the subject of the
 * token, followed by an '@' followed by the issuer of the token.
 */
@Getter
public class ExtendedJwtClientValidator extends JWTClientValidator {

    private ClientModel client;
    private final int currentTime;

    public ExtendedJwtClientValidator(ClientAuthenticationFlowContext context, String clientAuthenticatorProviderId) {
        super(context, clientAuthenticatorProviderId);
        currentTime = Time.currentTime();
    }

    @Override
    public boolean validateClient() {
        if (getToken() == null) {
            throw new IllegalStateException("Incorrect usage. Variable 'token' is null. Need to read JWS first before validateClient");
        }

        String serviceAccount = getToken().getSubject();
        if (serviceAccount == null) {
            throw new TokenValidationException("Can't identify client. Subject missing on JWT token");
        }

        Optional<ClientModel> clientOptional = getRealm().getClientsStream()
            .filter(this::requestedClientPredicate)
            .findFirst();

        if (clientOptional.isEmpty()) {
            getContext().failure(CLIENT_NOT_FOUND, null);
            return false;
        }

        client = clientOptional.get();
        getContext().setClient(client);

        if (!client.isEnabled()) {
            getContext().failure(CLIENT_DISABLED, null);
            return false;
        }

        return true;
    }

    private boolean requestedClientPredicate(ClientModel c) {
        if (StringUtil.isNullOrEmpty(c.getDescription())) {
            return false;
        }

        String expectedClientIssuerLine = getToken().getSubject() + "@" + getToken().getIssuer();
        return Arrays.asList(c.getDescription().split("\r\n|\n|\r"))
            .contains(expectedClientIssuerLine);
    }

    @Override
    public boolean validateSignatureAlgorithm() {
        if (getJws() == null) {
            throw new IllegalStateException("Incorrect usage. Variable 'jws' is null. Need to read token first before validate signature algorithm");
        }
        if (client == null) {
            throw new IllegalStateException("Incorrect usage. Variable 'client' is null. Need to validate client first before validate signature algorithm");
        }

        String expectedSignatureAlg = OIDCAdvancedConfigWrapper.fromClientModel(client).getTokenEndpointAuthSigningAlg();
        if (getJws().getHeader().getAlgorithm() == null) {
            Response challengeResponse = ClientAuthUtil.errorResponse(BAD_REQUEST.getStatusCode(), "invalid_client", "invalid signature algorithm");
            getContext().challenge(challengeResponse);
            return false;
        }

        String actualSignatureAlg = getJws().getHeader().getAlgorithm().name();
        if (expectedSignatureAlg != null && !Objects.equals(expectedSignatureAlg, actualSignatureAlg)) {
            Response challengeResponse = ClientAuthUtil.errorResponse(BAD_REQUEST.getStatusCode(), "invalid_client", "invalid signature algorithm");
            getContext().challenge(challengeResponse);
            return false;
        }

        return true;
    }

    @Override
    public void validateTokenReuse() {
        if (getToken() == null) {
            throw new IllegalStateException("Incorrect usage. Variable 'token' is null. Need to read token first before validateToken reuse");
        }
        if (client == null) {
            throw new IllegalStateException("Incorrect usage. Variable 'client' is null. Need to validate client first before validateToken reuse");
        }
        // disable check for token reuse as pods may send multiple requests with the same service account token
    }

    @Override
    public void validateToken() {
        if (getToken() == null) {
            throw new IllegalStateException("Incorrect usage. Variable 'token' is null. Need to read token first before validateToken");
        }

        if (!getToken().isActive()) {
            throw new TokenValidationException("Token is not active");
        }

        // KEYCLOAK-2986, token-timeout or token-expiration in keycloak.json might not be used
        if (getToken().getExp() == 0 && getToken().getIat() + 10 < getCurrentTime()) {
            throw new TokenValidationException("Token is not active");
        }

        // disable check for token id as kubernetes do not write any ids into the token.
    }
}

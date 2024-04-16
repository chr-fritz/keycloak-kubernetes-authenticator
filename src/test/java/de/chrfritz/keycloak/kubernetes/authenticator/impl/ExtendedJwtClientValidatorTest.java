package de.chrfritz.keycloak.kubernetes.authenticator.impl;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator.ReplaceUnderscores;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@DisplayNameGeneration(ReplaceUnderscores.class)
@ExtendWith(MockitoExtension.class)
class ExtendedJwtClientValidatorTest {

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private ClientAuthenticationFlowContext context;

    @Mock
    private ClientModel client;

    @InjectMocks
    private ExtendedJwtClientValidator validator;

    @BeforeEach
    void setUp() {
        when(context.getRealm().getClientsStream()).thenReturn(Stream.of(client));
        when(context.getHttpRequest().getHttpHeaders().getMediaType()).thenReturn(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        MultivaluedMap<String, String> parameters = context.getHttpRequest().getDecodedFormParameters();
        when(parameters.getFirst(OAuth2Constants.CLIENT_ASSERTION_TYPE)).thenReturn(OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT);

        when(client.getDescription()).thenReturn("\nsystem:serviceaccount:dummy:dummy@http://issuer");
        lenient().when(client.isEnabled()).thenReturn(true);
    }

    @Test
    void test_validateToken_successfully() throws JWSInputException {
        mockToken("system:serviceaccount:dummy:dummy", "http://issuer", -1, -1, 60);

        assertThat(validator.clientAssertionParametersValidation()).isTrue();

        validator.readJws();

        assertThat(validator.validateClient()).isTrue();
        validator.validateToken();
    }

    @Test
    void test_validateToken_expired() throws JWSInputException {
        mockToken("system:serviceaccount:dummy:dummy", "http://issuer", -1, -1, -60);

        assertThat(validator.clientAssertionParametersValidation()).isTrue();

        validator.readJws();

        assertThat(validator.validateClient()).isTrue();
        assertThatThrownBy(() -> validator.validateToken()).isInstanceOf(TokenValidationException.class);
    }

    @Test
    void test_validateToken_not_yet_valid() throws JWSInputException {
        mockToken("system:serviceaccount:dummy:dummy", "http://issuer", -1, 30, 60);

        assertThat(validator.clientAssertionParametersValidation()).isTrue();

        validator.readJws();

        assertThat(validator.validateClient()).isTrue();
        assertThatThrownBy(() -> validator.validateToken()).isInstanceOf(TokenValidationException.class);
    }

    @Test
    void test_validateToken_issued_in_future() throws JWSInputException {
        mockToken("system:serviceaccount:dummy:dummy", "http://issuer", 30, 30, 60);

        assertThat(validator.clientAssertionParametersValidation()).isTrue();

        validator.readJws();

        assertThat(validator.validateClient()).isTrue();
        assertThatThrownBy(() -> validator.validateToken()).isInstanceOf(TokenValidationException.class);
    }

    @Test
    void test_validateToken_missing_client() throws JWSInputException {
        mockToken("system:serviceaccount:dummy:dummy1", "http://other", 30, 30, 60);

        assertThat(validator.clientAssertionParametersValidation()).isTrue();

        validator.readJws();

        assertThat(validator.validateClient()).isFalse();
    }

    @Test
    void test_validateToken_disabled_client() throws JWSInputException {
        mockToken("system:serviceaccount:dummy:dummy", "http://issuer", 30, 30, 60);
        when(client.isEnabled()).thenReturn(false);

        assertThat(validator.clientAssertionParametersValidation()).isTrue();

        validator.readJws();

        assertThat(validator.validateClient()).isFalse();
    }

    private void mockToken(String subject, String issuer, int diffIat, int diffNbf, int diffExp) {
        MultivaluedMap<String, String> parameters = context.getHttpRequest().getDecodedFormParameters();
        when(parameters.getFirst(OAuth2Constants.CLIENT_ASSERTION))
            .thenReturn(new JWSBuilder().type("JWT")
                .jsonContent(Map.of(
                    "sub", subject,
                    "iat", validator.getCurrentTime() + diffIat,
                    "exp", validator.getCurrentTime() + diffExp,
                    "nbf", validator.getCurrentTime() + diffNbf,
                    "iss", issuer
                ))
                .none());
    }
}

package de.chrfritz.keycloak.kubernetes.authenticator.impl;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator.ReplaceUnderscores;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.HashMap;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.params.provider.Arguments.arguments;
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

        lenient().when(client.getDescription()).thenReturn("\nsystem:serviceaccount:dummy:dummy@http://issuer");
    }

    public static Stream<Arguments> validateTokenTests() {
        return Stream.of(
            arguments(mockToken("system:serviceaccount:dummy:dummy", "http://issuer", -1, -1, 60), true, true, null, true, null, null),
            arguments(mockToken("system:serviceaccount:dummy:dummy", "http://issuer", -1, -1, -60), true, true, null, true, null, TokenValidationException.class),
            arguments(mockToken("system:serviceaccount:dummy:dummy", "http://issuer", -1, 30, 60), true, true, null, true, null, TokenValidationException.class),
            arguments(mockToken("system:serviceaccount:dummy:dummy", "http://issuer", 30, 30, 60), true, true, null, true, null, TokenValidationException.class),
            arguments(mockToken("system:serviceaccount:dummy:dummy1", "http://other", 30, 30, 60), true, true, null, false, null, null),
            arguments(mockToken("system:serviceaccount:dummy:dummy", "http://issuer", 30, 30, 60), false, true, null, false, null, null),
            arguments(mockToken(null, "http://issuer", 30, 30, 60), false, true, null, false, TokenValidationException.class, null),
            arguments("", false, true, JWSInputException.class, false, null, null)
        );
    }

    @ParameterizedTest
    @MethodSource("validateTokenTests")
    void test_validateToken(
        String token,
        boolean isClientActive,
        boolean assertationParametersValid,
        Class<Throwable> expectedReadJwsEx,
        boolean clientValid,
        Class<Throwable> expectedValidateClient,
        Class<Throwable> expectedValidateToken
    ) {

        MultivaluedMap<String, String> parameters = context.getHttpRequest().getDecodedFormParameters();
        when(parameters.getFirst(OAuth2Constants.CLIENT_ASSERTION)).thenReturn(token);
        lenient().when(client.isEnabled()).thenReturn(isClientActive);


        assertThat(validator.clientAssertionParametersValidation()).isEqualTo(assertationParametersValid);

        if (expectedReadJwsEx != null) {
            assertThatThrownBy(() -> validator.readJws()).isInstanceOf(expectedReadJwsEx);
            return;
        } else {
            assertThatCode(() -> validator.readJws()).doesNotThrowAnyException();
        }


        if (clientValid) {
            assertThat(validator.validateClient()).isTrue();
            if (expectedValidateToken != null) {
                assertThatThrownBy(() -> validator.validateToken()).isInstanceOf(expectedValidateToken);
            } else {
                assertThatCode(() -> validator.validateToken()).doesNotThrowAnyException();
            }
        } else if (expectedValidateClient != null) {
            assertThatThrownBy(() -> validator.validateClient()).isInstanceOf(expectedValidateClient);
        } else {
            assertThat(validator.validateClient()).isFalse();
        }
    }


    private static String mockToken(String subject, String issuer, int diffIat, int diffNbf, int diffExp) {
        long epochSecond = Instant.now().getEpochSecond();
        HashMap<Object, Object> map = new HashMap<>();
        map.put("sub", subject);
        map.put("iat", epochSecond + diffIat);
        map.put("exp", epochSecond + diffExp);
        map.put("nbf", epochSecond + diffNbf);
        map.put("iss", issuer);

        return new JWSBuilder().type("JWT")
            .jsonContent(map)
            .none();
    }
}

package de.chrfritz.keycloak.kubernetes.authenticator.impl;

import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator.ReplaceUnderscores;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.jose.jws.JWSInputException;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URISyntaxException;
import java.util.List;
import java.util.stream.Stream;

import static de.chrfritz.keycloak.kubernetes.authenticator.impl.TestUtils.*;
import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * Unit test for the {@link ExtendedJwtClientValidator}.
 */
@DisplayNameGeneration(ReplaceUnderscores.class)
@ExtendWith(MockitoExtension.class)
class ExtendedJwtClientValidatorTest {

    public static Stream<Arguments> validateTokenTests() {
        return Stream.of(
            arguments(mockToken("system:serviceaccount:dummy:dummy", "http://issuer", "", -1, -1, 60), true, true, null, true, null, null),
            arguments(mockToken("system:serviceaccount:dummy:dummy", "http://issuer", "", -1, -1, -60), true, true, null, true, null, TokenValidationException.class),
            arguments(mockToken("system:serviceaccount:dummy:dummy", "http://issuer", "", -1, 30, 60), true, true, null, true, null, TokenValidationException.class),
            arguments(mockToken("system:serviceaccount:dummy:dummy", "http://issuer", "", 30, 30, 60), true, true, null, true, null, TokenValidationException.class),
            arguments(mockToken("system:serviceaccount:dummy:dummy1", "http://other", "", 30, 30, 60), true, true, null, false, null, null),
            arguments(mockToken("system:serviceaccount:dummy:dummy", "http://issuer", "", 30, 30, 60), false, true, null, false, null, null),
            arguments(mockToken(null, "http://issuer", "", 30, 30, 60), false, true, null, false, TokenValidationException.class, null),
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
    ) throws URISyntaxException {

        ClientAuthenticationFlowContext context = mockAuthenticationFlowContext(
            List.of(mockClient("client", "\nsystem:serviceaccount:dummy:dummy@http://issuer", isClientActive)),
            token
        );
        ExtendedJwtClientValidator validator = new ExtendedJwtClientValidator(context);

        assertThat(validator.clientAssertionParametersValidation()).isEqualTo(assertationParametersValid);
        if (expectedReadJwsEx != null) {
            assertThatThrownBy(validator::readJws).isInstanceOf(expectedReadJwsEx);
            return;
        } else {
            assertThatCode(validator::readJws).doesNotThrowAnyException();
        }


        if (clientValid) {
            assertThat(validator.validateClient()).isTrue();
            if (expectedValidateToken != null) {
                assertThatThrownBy(validator::validateToken).isInstanceOf(expectedValidateToken);
            } else {
                assertThatCode(validator::validateToken).doesNotThrowAnyException();
            }
        } else if (expectedValidateClient != null) {
            assertThatThrownBy(validator::validateClient).isInstanceOf(expectedValidateClient);
        } else {
            assertThat(validator.validateClient()).isFalse();
        }
    }
}

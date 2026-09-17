package net.ripe.db.whois.api.sso;

import net.ripe.db.whois.api.AuthServiceServerDummy;
import net.ripe.db.whois.common.sso.AuthServiceClient;
import net.ripe.db.whois.common.sso.AuthServiceClientException;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthServiceClientIdentityAdapterTest {

    private static final String API_KEY = "whois-test-adapter-key";
    private static final String EMAIL = "person@net.net";
    private static final String UUID = "906635c2-0405-429a-800b-0602bd716124";
    private static final String UNKNOWN_UUID = "00000000-0000-0000-0000-000000000000";

    @Test
    void realAuthServiceClientUsesAccountsContract() throws Exception {
        final AuthServiceClient client = new AuthServiceClient("", API_KEY);
        final AuthServiceServerDummy server = new AuthServiceServerDummy(client);
        ReflectionTestUtils.setField(server, "apiKey", API_KEY);
        server.start();

        try {
            assertThat(client.getUuid(EMAIL), is(UUID));
            assertThat(client.getUsername(UUID), is(EMAIL));

            final AuthServiceClientException exception = assertThrows(AuthServiceClientException.class,
                    () -> client.getUuid("unknown@example.com"));
            assertThat(exception.getCode(), is(401));

            final AuthServiceClientException unknownUuidException = assertThrows(AuthServiceClientException.class,
                    () -> client.getUserDetails(UNKNOWN_UUID));
            assertThat(unknownUuidException.getCode(), is(401));
        } finally {
            server.stop();
        }
    }
}

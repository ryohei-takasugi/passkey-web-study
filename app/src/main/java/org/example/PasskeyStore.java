package org.example;

import io.vertx.core.Future;
import io.vertx.ext.auth.webauthn4j.Authenticator;
import io.vertx.ext.auth.webauthn4j.CredentialStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class PasskeyStore implements CredentialStorage {

    private static final Logger log = LoggerFactory.getLogger(PasskeyStore.class);

    private final Map<String, List<Authenticator>> byUsername = new ConcurrentHashMap<>();
    private final Map<String, Authenticator>       byCredId   = new ConcurrentHashMap<>();

    @Override
    public Future<List<Authenticator>> find(String username, String credId) {
        log.debug("find: username={} credId={}", username, credId);
        if (credId != null) {
            Authenticator auth = byCredId.get(credId);
            return Future.succeededFuture(auth != null ? List.of(auth) : List.of());
        }
        if (username != null) {
            return Future.succeededFuture(
                new ArrayList<>(byUsername.getOrDefault(username, List.of()))
            );
        }
        return Future.succeededFuture(List.of());
    }

    @Override
    public Future<Void> storeCredential(Authenticator authenticator) {
        String username = authenticator.getUsername();
        String credId   = authenticator.getCredID();
        log.info("storeCredential: username={} credId={}", username, credId);

        byCredId.put(credId, authenticator);
        List<Authenticator> list = byUsername.computeIfAbsent(username, k -> new ArrayList<>());
        list.removeIf(a -> credId.equals(a.getCredID()));
        list.add(authenticator);
        return Future.succeededFuture();
    }

    @Override
    public Future<Void> updateCounter(Authenticator authenticator) {
        String credId = authenticator.getCredID();
        log.debug("updateCounter: credId={} counter={}", credId, authenticator.getCounter());

        Authenticator existing = byCredId.get(credId);
        if (existing != null) {
            existing.setCounter(authenticator.getCounter());
        }
        return Future.succeededFuture();
    }
}

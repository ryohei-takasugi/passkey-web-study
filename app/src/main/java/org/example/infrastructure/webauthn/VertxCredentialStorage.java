package org.example.infrastructure.webauthn;

import io.vertx.core.Future;
import io.vertx.ext.auth.webauthn4j.Authenticator;
import io.vertx.ext.auth.webauthn4j.CredentialStorage;
import org.example.domain.repository.CredentialRepository;

import java.util.List;

/**
 * CredentialStorage の実装。ドメイン層の CredentialRepository に委譲する。
 */
public class VertxCredentialStorage implements CredentialStorage {

    private final CredentialRepository repository;

    /**
     * @param repository 認証器データのリポジトリ
     */
    public VertxCredentialStorage(CredentialRepository repository) {
        this.repository = repository;
    }

    /** {@inheritDoc} */
    @Override
    public Future<List<Authenticator>> find(String username, String credId) {
        return repository.find(username, credId);
    }

    /** {@inheritDoc} */
    @Override
    public Future<Void> storeCredential(Authenticator authenticator) {
        return repository.store(authenticator);
    }

    /** {@inheritDoc} */
    @Override
    public Future<Void> updateCounter(Authenticator authenticator) {
        return repository.updateCounter(authenticator);
    }
}

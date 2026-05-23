package org.example.infrastructure.persistence;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn4j.Authenticator;
import org.example.domain.repository.CredentialRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * credentials.json に認証器データを永続化する CredentialRepository 実装。
 */
public class JsonFileCredentialRepository implements CredentialRepository {

    private static final Logger log = LoggerFactory.getLogger(JsonFileCredentialRepository.class);

    private final Vertx vertx;
    private final String filePath;

    /**
     * @param vertx    Vert.x インスタンス
     * @param filePath credentials.json のパス
     */
    public JsonFileCredentialRepository(Vertx vertx, String filePath) {
        this.vertx    = vertx;
        this.filePath = filePath;
    }

    /** {@inheritDoc} */
    @Override
    public Future<List<Authenticator>> find(String userId, String credId) {
        return readAll().map(all -> doFind(all, userId, credId));
    }

    /** {@inheritDoc} */
    @Override
    public Future<Void> store(Authenticator authenticator) {
        String userId = authenticator.getUsername();
        String credId = authenticator.getCredID();
        log.info("store: userId={} credId={}", userId, credId);

        return readAll()
            .map(all -> replaceOrAdd(all, userId, credId, authenticator))
            .compose(this::writeAll);
    }

    /** {@inheritDoc} */
    @Override
    public Future<Void> updateCounter(Authenticator authenticator) {
        String userId = authenticator.getUsername();
        String credId = authenticator.getCredID();
        log.debug("updateCounter: userId={} credId={} counter={}",
                  userId, credId, authenticator.getCounter());

        return readAll()
            .map(all -> patchCounter(all, userId, credId, authenticator.getCounter()))
            .compose(this::writeAll);
    }

    // ── 内部ヘルパー ─────────────────────────────────────────────────

    private Future<JsonObject> readAll() {
        return vertx.fileSystem().exists(filePath)
            .compose(exists -> exists
                ? vertx.fileSystem().readFile(filePath).map(JsonObject::new)
                : Future.succeededFuture(new JsonObject()));
    }

    private Future<Void> writeAll(JsonObject data) {
        return vertx.fileSystem().writeFile(filePath, data.toBuffer());
    }

    private List<Authenticator> doFind(JsonObject all, String userId, String credId) {
        if (credId != null) {
            return findByCredId(all, credId);
        }
        if (userId != null) {
            return findByUserId(all, userId);
        }
        return List.of();
    }

    private List<Authenticator> findByCredId(JsonObject all, String credId) {
        List<Authenticator> result = new ArrayList<>();
        for (String uid : all.fieldNames()) {
            all.getJsonArray(uid).stream()
               .map(o -> new Authenticator((JsonObject) o))
               .filter(a -> credId.equals(a.getCredID()))
               .forEach(result::add);
        }
        return result;
    }

    private List<Authenticator> findByUserId(JsonObject all, String userId) {
        JsonArray arr = all.getJsonArray(userId, new JsonArray());
        List<Authenticator> result = new ArrayList<>();
        arr.stream()
           .map(o -> new Authenticator((JsonObject) o))
           .forEach(result::add);
        return result;
    }

    private JsonObject replaceOrAdd(JsonObject all, String userId, String credId,
                                    Authenticator authenticator) {
        JsonArray existing = all.getJsonArray(userId, new JsonArray());
        JsonArray updated  = new JsonArray();

        existing.stream()
                .map(o -> (JsonObject) o)
                .filter(o -> !credId.equals(o.getString("credID")))
                .forEach(updated::add);

        updated.add(authenticator.toJson());
        return all.put(userId, updated);
    }

    private JsonObject patchCounter(JsonObject all, String userId, String credId, long counter) {
        JsonArray arr = all.getJsonArray(userId, new JsonArray());
        arr.stream()
           .map(o -> (JsonObject) o)
           .filter(o -> credId.equals(o.getString("credID")))
           .findFirst()
           .ifPresent(o -> o.put("counter", counter));
        return all;
    }
}

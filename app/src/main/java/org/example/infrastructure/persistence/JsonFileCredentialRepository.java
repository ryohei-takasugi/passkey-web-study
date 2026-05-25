package org.example.infrastructure.persistence;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.example.domain.model.CredentialRecord;
import org.example.domain.repository.CredentialRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * credentials.json にクレデンシャルを永続化する CredentialRepository 実装。
 */
public class JsonFileCredentialRepository implements CredentialRepository {

    private static final Logger logger = LoggerFactory.getLogger(JsonFileCredentialRepository.class);

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
    public Future<List<CredentialRecord>> find(String userId, String credentialId) {
        Future<JsonObject> allFuture = readAll();
        return allFuture.map(all -> {
            return doFind(all, userId, credentialId);
        });
    }

    /** {@inheritDoc} */
    @Override
    public Future<Void> store(CredentialRecord record) {
        logger.info("store: userId={} credentialId={}", record.userId(), record.credentialId());
        Future<JsonObject> allFuture = readAll();
        Future<JsonObject> updatedFuture = allFuture.map(all -> {
            return replaceOrAdd(all, record);
        });
        return updatedFuture.compose(updated -> {
            return writeAll(updated);
        });
    }

    /** {@inheritDoc} */
    @Override
    public Future<Void> updateCounter(String credentialId, long newCount) {
        logger.debug("updateCounter: credentialId={} newCount={}", credentialId, newCount);
        Future<JsonObject> allFuture = readAll();
        Future<JsonObject> patchedFuture = allFuture.map(all -> {
            return patchCounter(all, credentialId, newCount);
        });
        return patchedFuture.compose(patched -> {
            return writeAll(patched);
        });
    }

    // ── 内部ヘルパー ─────────────────────────────────────────────────

    private Future<JsonObject> readAll() {
        Future<Boolean> existsFuture = vertx.fileSystem().exists(filePath);
        return existsFuture.compose(exists -> {
            if (exists) {
                Future<Buffer> readFuture = vertx.fileSystem().readFile(filePath);
                return readFuture.map(buf -> {
                    return new JsonObject(buf);
                });
            } else {
                return Future.succeededFuture(new JsonObject());
            }
        });
    }

    private Future<Void> writeAll(JsonObject data) {
        return vertx.fileSystem().writeFile(filePath, data.toBuffer());
    }

    private List<CredentialRecord> doFind(JsonObject all, String userId, String credentialId) {
        if (credentialId != null) {
            return findByCredentialId(all, credentialId);
        }
        if (userId != null) {
            return findByUserId(all, userId);
        }
        return List.of();
    }

    private List<CredentialRecord> findByCredentialId(JsonObject all, String credentialId) {
        List<CredentialRecord> result = new ArrayList<>();
        for (String uid : all.fieldNames()) {
            all.getJsonArray(uid).stream()
               .map(o -> CredentialRecord.fromJson((JsonObject) o))
               .filter(r -> credentialId.equals(r.credentialId()))
               .forEach(result::add);
        }
        return result;
    }

    private List<CredentialRecord> findByUserId(JsonObject all, String userId) {
        JsonArray arr = all.getJsonArray(userId, new JsonArray());
        List<CredentialRecord> result = new ArrayList<>();
        arr.stream()
           .map(o -> CredentialRecord.fromJson((JsonObject) o))
           .forEach(result::add);
        return result;
    }

    private JsonObject replaceOrAdd(JsonObject all, CredentialRecord record) {
        String userId       = record.userId();
        String credentialId = record.credentialId();
        JsonArray existing  = all.getJsonArray(userId, new JsonArray());
        JsonArray updated   = new JsonArray();

        existing.stream()
                .map(o -> (JsonObject) o)
                .filter(o -> !credentialId.equals(o.getString("credentialId")))
                .forEach(updated::add);

        updated.add(record.toJson());
        return all.put(userId, updated);
    }

    private JsonObject patchCounter(JsonObject all, String credentialId, long newCount) {
        for (String uid : all.fieldNames()) {
            all.getJsonArray(uid).stream()
               .map(o -> (JsonObject) o)
               .filter(o -> credentialId.equals(o.getString("credentialId")))
               .findFirst()
               .ifPresent(o -> o.put("signCount", newCount));
        }
        return all;
    }
}

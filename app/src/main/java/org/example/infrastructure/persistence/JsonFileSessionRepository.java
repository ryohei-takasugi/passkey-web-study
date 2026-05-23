package org.example.infrastructure.persistence;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import org.example.domain.model.SessionInfo;
import org.example.domain.repository.SessionRepository;

/**
 * sessions.json からセッション情報を読み込む SessionRepository 実装。
 * 本番では外部セッション WebAPI を呼ぶ実装に差し替える。
 */
public class JsonFileSessionRepository implements SessionRepository {

    private final Vertx vertx;
    private final String filePath;

    /**
     * @param vertx    Vert.x インスタンス
     * @param filePath sessions.json のパス
     */
    public JsonFileSessionRepository(Vertx vertx, String filePath) {
        this.vertx    = vertx;
        this.filePath = filePath;
    }

    /** {@inheritDoc} */
    @Override
    public Future<SessionInfo> findSession(String sessionId) {
        return vertx.fileSystem().readFile(filePath)
            .map(buf -> new JsonObject(buf).getJsonObject(sessionId))
            .compose(json -> toSessionInfo(sessionId, json));
    }

    private Future<SessionInfo> toSessionInfo(String sessionId, JsonObject json) {
        if (json == null) {
            return Future.failedFuture("sessionId not found: " + sessionId);
        }
        return Future.succeededFuture(SessionInfo.fromJson(json));
    }
}

package org.example.infrastructure.session;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * セッション WebAPI のローカルファイル実装。
 * 本番環境では外部 HTTP クライアントに差し替える。
 */
public class SessionWebAPIClient {

    private static final Logger logger = LoggerFactory.getLogger(SessionWebAPIClient.class);

    private final Vertx vertx;
    private final String filePath;

    /**
     * @param vertx    Vert.x インスタンス
     * @param filePath sessions.json のパス
     */
    public SessionWebAPIClient(Vertx vertx, String filePath) {
        this.vertx    = vertx;
        this.filePath = filePath;
    }

    /**
     * sessionId に対応するセッション JSON を返す。
     * 存在しない場合は null を返す（失敗 Future ではない）。
     *
     * @param sessionId セッション ID
     * @return セッション JSON、存在しない場合は null
     */
    public Future<JsonObject> find(String sessionId) {
        Future<Boolean> existsFuture = vertx.fileSystem().exists(filePath);
        return existsFuture.compose(exists -> {
            if (!exists) {
                return Future.succeededFuture(null);
            }
            Future<Buffer> readFuture = vertx.fileSystem().readFile(filePath);
            return readFuture.map(buf -> {
                return new JsonObject(buf).getJsonObject(sessionId);
            });
        });
    }

    /**
     * sessionId のセッションに updates をマージして保存する。
     * updates の値が null のキーは既存セッションから削除する。
     *
     * @param sessionId セッション ID
     * @param updates   マージするキーと値のマップ
     * @return 完了 Future
     */
    public Future<Void> put(String sessionId, JsonObject updates) {
        logger.debug("put: sessionId={} updates={}", sessionId, updates.encode());
        Future<Boolean> existsFuture = vertx.fileSystem().exists(filePath);
        return existsFuture.compose(exists -> {
            Future<Buffer> readFuture = exists
                    ? vertx.fileSystem().readFile(filePath)
                    : Future.succeededFuture(Buffer.buffer("{}"));
            return readFuture.compose(buf -> {
                JsonObject all     = new JsonObject(buf);
                JsonObject session = all.getJsonObject(sessionId, new JsonObject());
                for (String key : updates.fieldNames()) {
                    if (updates.getValue(key) == null) {
                        session.remove(key);
                    } else {
                        session.put(key, updates.getValue(key));
                    }
                }
                all.put(sessionId, session);
                return vertx.fileSystem().writeFile(filePath, all.toBuffer());
            });
        });
    }
}

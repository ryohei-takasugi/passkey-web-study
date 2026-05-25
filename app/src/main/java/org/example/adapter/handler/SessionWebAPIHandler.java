package org.example.adapter.handler;

import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.http.Cookie;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.example.infrastructure.session.SessionWebAPIClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * sessionId Cookie でセッション情報を読み込み、ctx に共有するプリハンドラー。
 * Cookie 未設定またはセッション未発見の場合はそのまま次のハンドラーに進む。
 */
public class SessionWebAPIHandler implements Handler<RoutingContext> {

    /** ctx に格納するセッション JSON のキー。 */
    public static final String CTX_SESSION_KEY    = "session";

    /** ctx に格納するセッション ID のキー。 */
    public static final String CTX_SESSION_ID_KEY = "sessionId";

    private static final Logger logger = LoggerFactory.getLogger(SessionWebAPIHandler.class);

    private final SessionWebAPIClient sessionWebAPIClient;

    /**
     * @param sessionWebAPIClient セッション WebAPI クライアント
     */
    public SessionWebAPIHandler(SessionWebAPIClient sessionWebAPIClient) {
        this.sessionWebAPIClient = sessionWebAPIClient;
    }

    /** {@inheritDoc} */
    @Override
    public void handle(RoutingContext ctx) {
        Cookie cookie = ctx.request().getCookie("sessionId");
        if (cookie == null) {
            ctx.next();
            return;
        }
        String sessionId = cookie.getValue();
        Future<JsonObject> findFuture = sessionWebAPIClient.find(sessionId);
        findFuture.onSuccess(sessionJson -> {
            if (sessionJson != null) {
                ctx.put(CTX_SESSION_ID_KEY, sessionId);
                ctx.put(CTX_SESSION_KEY, sessionJson);
                logger.debug("session loaded: sessionId={}", sessionId);
            }
            ctx.next();
        });
        findFuture.onFailure(err -> {
            logger.warn("session load failed: {}", err.getMessage());
            ctx.next();
        });
    }
}

package org.example.adapter.handler;

import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

/**
 * GET /api/user を処理するハンドラー。
 * 認証済みユーザーの情報を JSON で返す。未認証の場合は 401 を返す。
 */
public class UserInfoHandler implements Handler<RoutingContext> {

    /** {@inheritDoc} */
    @Override
    public void handle(RoutingContext ctx) {
        JsonObject sessionJson = ctx.get(SessionWebAPIHandler.CTX_SESSION_KEY);
        if (sessionJson == null) {
            ctx.response().setStatusCode(401).end();
            return;
        }
        String userId = sessionJson.getString("userId");
        ctx.response()
                .putHeader("content-type", "application/json")
                .end(new JsonObject().put("userId", userId).encode());
    }
}

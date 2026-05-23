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
        if (ctx.user() == null) {
            ctx.response()
               .setStatusCode(401)
               .end(new JsonObject().put("error", "Unauthorized").encode());
            return;
        }
        ctx.response()
           .putHeader("content-type", "application/json")
           .end(new JsonObject()
               .put("userId", ctx.user().principal().getString("sub"))
               .encode());
    }
}

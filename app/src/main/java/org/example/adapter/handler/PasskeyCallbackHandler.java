package org.example.adapter.handler;

import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn4j.WebAuthn4J;
import io.vertx.ext.auth.webauthn4j.WebAuthn4JCredentials;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.SessionHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * POST /webauthn/callback を処理するハンドラー。
 * 登録・認証の両フローで共用される。チャレンジ検証後に SessionHandler.setUser() でユーザーをセッションに保存する。
 */
public class PasskeyCallbackHandler implements Handler<RoutingContext> {

    private static final Logger log = LoggerFactory.getLogger(PasskeyCallbackHandler.class);

    private final WebAuthn4J webAuthn;
    private final SessionHandler sessionHandler;

    /**
     * @param webAuthn       WebAuthn4J インスタンス
     * @param sessionHandler セッションハンドラー（ユーザーのセッション保存に使用）
     */
    public PasskeyCallbackHandler(WebAuthn4J webAuthn, SessionHandler sessionHandler) {
        this.webAuthn       = webAuthn;
        this.sessionHandler = sessionHandler;
    }

    /** {@inheritDoc} */
    @Override
    public void handle(RoutingContext ctx) {
        String challenge = ctx.session().get(PasskeyRegisterHandler.SESSION_CHALLENGE_KEY);
        if (challenge == null) {
            respondError(ctx, 400, "no challenge in session");
            return;
        }

        String username = ctx.session().get(PasskeyRegisterHandler.SESSION_USER_ID_KEY);

        WebAuthn4JCredentials credentials = buildCredentials(ctx, challenge, username);

        webAuthn.authenticate(credentials)
            .compose(user -> {
                ctx.session().remove(PasskeyRegisterHandler.SESSION_CHALLENGE_KEY);
                ctx.session().remove(PasskeyRegisterHandler.SESSION_USER_ID_KEY);
                log.info("callback ok: principal={}", user.principal());
                return sessionHandler.setUser(ctx, user);
            })
            .onSuccess(v -> ctx.response()
                               .putHeader("content-type", "application/json")
                               .end(new JsonObject().put("status", "ok").encode()))
            .onFailure(err -> respondError(ctx, 400, err.getMessage()));
    }

    // ── プライベートヘルパー ────────────────────────────────────────

    private WebAuthn4JCredentials buildCredentials(RoutingContext ctx, String challenge,
                                                    String username) {
        return new WebAuthn4JCredentials()
            .setChallenge(challenge)
            .setWebauthn(ctx.body().asJsonObject())
            .setOrigin("http://localhost:8080")
            .setDomain("localhost")
            .setUsername(username != null ? username : "");
    }

    private void respondError(RoutingContext ctx, int status, String message) {
        log.warn("callback error: {}", message);
        ctx.response()
           .setStatusCode(status)
           .end(new JsonObject().put("error", message).encode());
    }
}

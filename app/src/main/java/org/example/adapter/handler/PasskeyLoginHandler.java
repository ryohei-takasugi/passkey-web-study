package org.example.adapter.handler;

import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.http.Cookie;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn4j.WebAuthn4J;
import io.vertx.ext.web.RoutingContext;
import org.example.domain.model.SessionInfo;
import org.example.domain.model.UserId;
import org.example.domain.repository.SessionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * POST /webauthn/login を処理するハンドラー。
 * sessionId Cookie からユーザーIDを解決し、WebAuthn アサーションオプションを返す。
 */
public class PasskeyLoginHandler implements Handler<RoutingContext> {

    private static final Logger log = LoggerFactory.getLogger(PasskeyLoginHandler.class);

    private final WebAuthn4J webAuthn;
    private final SessionRepository sessionRepository;

    /**
     * @param webAuthn          WebAuthn4J インスタンス
     * @param sessionRepository セッションリポジトリ
     */
    public PasskeyLoginHandler(WebAuthn4J webAuthn, SessionRepository sessionRepository) {
        this.webAuthn          = webAuthn;
        this.sessionRepository = sessionRepository;
    }

    /** {@inheritDoc} */
    @Override
    public void handle(RoutingContext ctx) {
        Cookie cookie = ctx.request().getCookie("sessionId");
        if (cookie == null) {
            respondError(ctx, 400, "sessionId cookie is required");
            return;
        }

        sessionRepository.findSession(cookie.getValue())
            .compose(this::verifyAndResolveUserId)
            .compose(userId -> buildAssertionOptions(userId)
                .onSuccess(opts -> ctx.session().put(PasskeyRegisterHandler.SESSION_USER_ID_KEY, userId.value())))
            .onSuccess(options -> saveAndRespond(ctx, options))
            .onFailure(err    -> respondError(ctx, 400, err.getMessage()));
    }

    // ── プライベートヘルパー ────────────────────────────────────────

    private Future<UserId> verifyAndResolveUserId(SessionInfo session) {
        try {
            session.requireAuthenticated();
            return Future.succeededFuture(UserId.of(session.userId()));
        } catch (IllegalStateException e) {
            return Future.failedFuture(e);
        }
    }

    private Future<JsonObject> buildAssertionOptions(UserId userId) {
        return webAuthn.getCredentialsOptions(userId.value());
    }

    private void saveAndRespond(RoutingContext ctx, JsonObject options) {
        ctx.session().put(PasskeyRegisterHandler.SESSION_CHALLENGE_KEY,
                          options.getString("challenge"));
        log.debug("login options issued");
        ctx.response()
           .putHeader("content-type", "application/json")
           .end(options.encode());
    }

    private void respondError(RoutingContext ctx, int status, String message) {
        log.warn("login error: {}", message);
        ctx.response()
           .setStatusCode(status)
           .end(new JsonObject().put("error", message).encode());
    }
}

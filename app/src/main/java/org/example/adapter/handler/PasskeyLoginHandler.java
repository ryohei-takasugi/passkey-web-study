package org.example.adapter.handler;

import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.example.domain.model.SessionInfo;
import org.example.domain.model.UserId;
import org.example.infrastructure.session.SessionWebAPIClient;
import org.example.infrastructure.webauthn.WebAuthnService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * POST /webauthn/login を処理するハンドラー。
 * SessionWebAPIHandler が ctx にセットしたセッション情報からユーザーIDを解決し、
 * WebAuthn アサーションオプションを返す。
 */
public class PasskeyLoginHandler implements Handler<RoutingContext> {

    private static final Logger logger = LoggerFactory.getLogger(PasskeyLoginHandler.class);

    private final WebAuthnService webAuthnService;
    private final SessionWebAPIClient sessionWebAPIClient;

    /**
     * @param webAuthnService     WebAuthn サービス
     * @param sessionWebAPIClient セッション WebAPI クライアント
     */
    public PasskeyLoginHandler(WebAuthnService webAuthnService,
            SessionWebAPIClient sessionWebAPIClient) {
        this.webAuthnService     = webAuthnService;
        this.sessionWebAPIClient = sessionWebAPIClient;
    }

    /** {@inheritDoc} */
    @Override
    public void handle(RoutingContext ctx) {
        JsonObject sessionJson = ctx.get(SessionWebAPIHandler.CTX_SESSION_KEY);
        if (sessionJson == null) {
            respondError(ctx, 400, "session not found");
            return;
        }
        String sessionId = ctx.get(SessionWebAPIHandler.CTX_SESSION_ID_KEY);

        UserId userId;
        try {
            SessionInfo sessionInfo = SessionInfo.fromJson(sessionJson);
            sessionInfo.requireAuthenticated();
            userId = UserId.of(sessionInfo.userId());
        } catch (IllegalStateException e) {
            respondError(ctx, 400, e.getMessage());
            return;
        }

        Future<JsonObject> authOptsFuture = webAuthnService.createAuthenticationOptions(userId.value());
        authOptsFuture.compose(options -> {
            String challenge = options.getString("challenge");
            JsonObject updates = new JsonObject()
                    .put(PasskeyRegisterHandler.SESSION_CHALLENGE_KEY, challenge)
                    .put(PasskeyRegisterHandler.SESSION_USER_ID_KEY, userId.value())
                    .put(WebAuthnService.SESSION_FLOW_KEY, WebAuthnService.FLOW_LOGIN);
            Future<Void> putFuture = sessionWebAPIClient.put(sessionId, updates);
            return putFuture.map(v -> {
                return options;
            });
        }).onSuccess(options -> {
            logger.debug("login options issued");
            ctx.response()
                    .putHeader("content-type", "application/json")
                    .end(options.encode());
        }).onFailure(err -> {
            respondError(ctx, 400, err.getMessage());
        });
    }

    // ── プライベートヘルパー ────────────────────────────────────────

    private void respondError(RoutingContext ctx, int status, String message) {
        logger.warn("login error: {}", message);
        ctx.response()
                .setStatusCode(status)
                .end(new JsonObject().put("error", message).encode());
    }
}

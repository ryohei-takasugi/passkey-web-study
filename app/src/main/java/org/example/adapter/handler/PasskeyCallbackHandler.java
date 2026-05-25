package org.example.adapter.handler;

import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.example.domain.model.CredentialRecord;
import org.example.infrastructure.session.SessionWebAPIClient;
import org.example.infrastructure.webauthn.WebAuthnService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * POST /webauthn/callback を処理するハンドラー。
 * 登録・認証の両フローで共用される。チャレンジ検証後にセッションの WebAuthn 一時データを削除する。
 */
public class PasskeyCallbackHandler implements Handler<RoutingContext> {

    private static final Logger logger = LoggerFactory.getLogger(PasskeyCallbackHandler.class);

    private final WebAuthnService webAuthnService;
    private final SessionWebAPIClient sessionWebAPIClient;

    /**
     * @param webAuthnService     WebAuthn サービス
     * @param sessionWebAPIClient セッション WebAPI クライアント
     */
    public PasskeyCallbackHandler(WebAuthnService webAuthnService,
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

        String challenge = sessionJson.getString(PasskeyRegisterHandler.SESSION_CHALLENGE_KEY);
        String userId    = sessionJson.getString(PasskeyRegisterHandler.SESSION_USER_ID_KEY);
        String flow      = sessionJson.getString(WebAuthnService.SESSION_FLOW_KEY);

        if (challenge == null || userId == null || flow == null) {
            respondError(ctx, 400, "invalid session state");
            return;
        }

        Future<CredentialRecord> verifyFuture = WebAuthnService.FLOW_REGISTER.equals(flow)
                ? webAuthnService.verifyRegistration(challenge, userId, ctx.body().asJsonObject())
                : webAuthnService.verifyAuthentication(challenge, userId, ctx.body().asJsonObject());

        verifyFuture.compose(record -> {
            logger.info("callback ok: flow={} userId={}", flow, record.userId());
            JsonObject clearUpdates = new JsonObject()
                    .putNull(PasskeyRegisterHandler.SESSION_CHALLENGE_KEY)
                    .putNull(PasskeyRegisterHandler.SESSION_USER_ID_KEY)
                    .putNull(WebAuthnService.SESSION_FLOW_KEY);
            return sessionWebAPIClient.put(sessionId, clearUpdates);
        }).onSuccess(v -> {
            ctx.response()
                    .putHeader("content-type", "application/json")
                    .end(new JsonObject().put("status", "ok").encode());
        }).onFailure(err -> {
            respondError(ctx, 400, err.getMessage());
        });
    }

    // ── プライベートヘルパー ────────────────────────────────────────

    private void respondError(RoutingContext ctx, int status, String message) {
        logger.warn("callback error: {}", message);
        ctx.response()
                .setStatusCode(status)
                .end(new JsonObject().put("error", message).encode());
    }
}

package org.example;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.auth.webauthn4j.Attestation;
import io.vertx.ext.auth.webauthn4j.COSEAlgorithm;
import io.vertx.ext.auth.webauthn4j.RelyingParty;
import io.vertx.ext.auth.webauthn4j.UserVerification;
import io.vertx.ext.auth.webauthn4j.WebAuthn4J;
import io.vertx.ext.auth.webauthn4j.WebAuthn4JOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.SessionHandler;
import io.vertx.ext.web.handler.StaticHandler;
import io.vertx.ext.web.sstore.LocalSessionStore;
import org.example.adapter.handler.PasskeyCallbackHandler;
import org.example.adapter.handler.PasskeyLoginHandler;
import org.example.adapter.handler.PasskeyRegisterHandler;
import org.example.adapter.handler.UserInfoHandler;
import org.example.domain.repository.CredentialRepository;
import org.example.domain.repository.SessionRepository;
import org.example.infrastructure.persistence.JsonFileCredentialRepository;
import org.example.infrastructure.persistence.JsonFileSessionRepository;
import org.example.infrastructure.webauthn.VertxCredentialStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * アプリケーションのエントリポイントおよび Vert.x Verticle。
 * HTTP サーバーの起動と Router の配線のみを担当する。
 */
public class MainVerticle extends AbstractVerticle {

    private static final Logger log = LoggerFactory.getLogger(MainVerticle.class);

    /**
     * アプリケーションを起動する。
     *
     * @param args 起動引数（未使用）
     */
    public static void main(String[] args) {
        Vertx vertx = Vertx.vertx();
        vertx.deployVerticle(new MainVerticle())
             .onSuccess(id -> log.info("MainVerticle deployed: {}", id))
             .onFailure(err -> {
                 log.error("Failed to start", err);
                 vertx.close();
             });
    }

    /** {@inheritDoc} */
    @Override
    public void start(Promise<Void> startPromise) {
        CredentialRepository credRepo = new JsonFileCredentialRepository(vertx, "credentials.json");
        SessionRepository    sessRepo = new JsonFileSessionRepository(vertx, "sessions.json");

        SessionHandler sessionHandler = SessionHandler.create(LocalSessionStore.create(vertx));
        WebAuthn4J     webAuthn       = buildWebAuthn(credRepo);
        Router         router         = buildRouter(webAuthn, sessRepo, sessionHandler);

        Future<HttpServer> fut = vertx.createHttpServer().requestHandler(router).listen(8080);
        fut.onSuccess(server -> {
                 log.info("HTTP server started on port:" + server.actualPort());
                 startPromise.complete();
             }).onFailure(startPromise::fail);
    }

    /**
     * WebAuthn4J インスタンスを構築する。
     *
     * @param credRepo 認証器データリポジトリ
     * @return 設定済み WebAuthn4J インスタンス
     */
    private WebAuthn4J buildWebAuthn(CredentialRepository credRepo) {
        WebAuthn4JOptions options = new WebAuthn4JOptions()
            .setRelyingParty(new RelyingParty().setId("localhost").setName("Passkey Demo"))
            .setUserVerification(UserVerification.REQUIRED)
            .setAttestation(Attestation.NONE)
            .setRequireResidentKey(false)
            .addPubKeyCredParam(COSEAlgorithm.ES256)
            .addPubKeyCredParam(COSEAlgorithm.RS256);

        return WebAuthn4J.create(vertx, options)
                         .credentialStorage(new VertxCredentialStorage(credRepo));
    }

    /**
     * Router を構築し、各ルートにハンドラーを配線する。
     *
     * @param webAuthn       WebAuthn4J インスタンス
     * @param sessRepo       セッションリポジトリ
     * @param sessionHandler セッションハンドラー
     * @return 設定済み Router
     */
    private Router buildRouter(WebAuthn4J webAuthn, SessionRepository sessRepo,
                                SessionHandler sessionHandler) {
        Router router = Router.router(vertx);

        router.route().handler(sessionHandler);
        router.route().handler(BodyHandler.create());

        router.post("/webauthn/register").handler(new PasskeyRegisterHandler(webAuthn, sessRepo));
        router.post("/webauthn/login").handler(new PasskeyLoginHandler(webAuthn, sessRepo));
        router.post("/webauthn/callback").handler(new PasskeyCallbackHandler(webAuthn, sessionHandler));

        router.get("/api/user").handler(new UserInfoHandler());
        router.get("/*").handler(StaticHandler.create("webroot"));

        return router;
    }
}

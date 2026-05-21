package org.example;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.ext.auth.webauthn4j.Attestation;
import io.vertx.ext.auth.webauthn4j.COSEAlgorithm;
import io.vertx.ext.auth.webauthn4j.RelyingParty;
import io.vertx.ext.auth.webauthn4j.UserVerification;
import io.vertx.ext.auth.webauthn4j.WebAuthn4J;
import io.vertx.ext.auth.webauthn4j.WebAuthn4JOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.SessionHandler;
import io.vertx.ext.web.handler.StaticHandler;
import io.vertx.ext.web.handler.WebAuthn4JHandler;
import io.vertx.ext.web.sstore.LocalSessionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MainVerticle extends AbstractVerticle {

    private static final Logger log = LoggerFactory.getLogger(MainVerticle.class);

    @Override
    public void start(Promise<Void> startPromise) {
        PasskeyStore store = new PasskeyStore();

        // Router を先に作成（WebAuthn4JHandler が Route 参照を必要とするため）
        Router router = Router.router(vertx);
        router.route().handler(SessionHandler.create(LocalSessionStore.create(vertx)));
        router.route().handler(BodyHandler.create());

        WebAuthn4JOptions options = new WebAuthn4JOptions()
            .setRelyingParty(new RelyingParty()
                .setId("localhost")
                .setName("Passkey Demo"))
            .setUserVerification(UserVerification.REQUIRED)
            .setAttestation(Attestation.NONE)
            .setRequireResidentKey(false)
            .addPubKeyCredParam(COSEAlgorithm.ES256)
            .addPubKeyCredParam(COSEAlgorithm.RS256);

        WebAuthn4J webAuthn = WebAuthn4J.create(vertx, options)
            .credentialStorage(store);

        // setup* はルート参照を保存するだけ。onOrder が呼ばれて初めて mount* が実行される。
        // onOrder は route.handler(webAuthn4JHandler) 時にトリガーされるため、
        // 必ずどこかのルートに handler として登録する必要がある。
        var webAuthn4JHandler = WebAuthn4JHandler.create(webAuthn)
            .setOrigin("http://localhost:8080")
            .setupCallback(router.post("/webauthn/callback"))
            .setupCredentialsCreateCallback(router.post("/webauthn/register"))
            .setupCredentialsGetCallback(router.post("/webauthn/login"));

        // この登録が onOrder をトリガーし、上記 setup* のルートが有効化される。
        // 同時に /api/user を認証済みユーザー専用エンドポイントとして提供する。
        router.get("/api/user").handler(webAuthn4JHandler).handler(ctx ->
            ctx.response()
               .putHeader("content-type", "application/json")
               .end(new JsonObject()
                       .put("username", ctx.user().principal().getString("sub"))
                       .encode())
        );

        // 静的ファイル (resources/webroot/ に index.html を配置)
        router.get("/*").handler(StaticHandler.create("webroot"));

        vertx.createHttpServer()
            .requestHandler(router)
            .listen(8080)
            .<Void>mapEmpty()
            .onSuccess(v -> {
                log.info("HTTP server started on http://localhost:8080");
                startPromise.complete();
            })
            .onFailure(startPromise::fail);
    }
}

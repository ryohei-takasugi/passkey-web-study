package org.example;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.StaticHandler;
import org.example.adapter.handler.PasskeyCallbackHandler;
import org.example.adapter.handler.PasskeyLoginHandler;
import org.example.adapter.handler.PasskeyRegisterHandler;
import org.example.adapter.handler.SessionWebAPIHandler;
import org.example.adapter.handler.UserInfoHandler;
import org.example.domain.repository.CredentialRepository;
import org.example.infrastructure.persistence.JsonFileCredentialRepository;
import org.example.infrastructure.session.SessionWebAPIClient;
import org.example.infrastructure.webauthn.WebAuthnService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

/**
 * アプリケーションのエントリポイントおよび Vert.x Verticle。
 * HTTP サーバーの起動と Router の配線のみを担当する。
 */
public class MainVerticle extends AbstractVerticle {

    private static final Logger logger = LoggerFactory.getLogger(MainVerticle.class);

    /**
     * アプリケーションを起動する。
     *
     * @param args 起動引数（未使用）
     */
    public static void main(String[] args) {
        Vertx vertx = Vertx.vertx();
        Future<String> fut = vertx.deployVerticle(new MainVerticle());
        fut.onSuccess(id -> {
            logger.info("MainVerticle deployed: {}", id);

        }).onFailure(err -> {
            logger.error("Failed to start", err);
            vertx.close();
        });
    }

    /** {@inheritDoc} */
    @Override
    public void start(Promise<Void> startPromise) {
        logger.info("working directory: {}", System.getProperty("user.dir"));
        String sessionsPath    = resolveDataPath("sessions.json");
        String credentialsPath = resolveDataPath("credentials.json");
        logger.info("data files: sessions={} credentials={}", sessionsPath, credentialsPath);

        SessionWebAPIClient sessionWebAPIClient = new SessionWebAPIClient(vertx, sessionsPath);
        WebAuthnService webAuthnService = createWebAuthnService(credentialsPath);
        Router router = buildRouter(webAuthnService, sessionWebAPIClient);

        Future<HttpServer> serverFuture = vertx.createHttpServer().requestHandler(router).listen(8081);
        serverFuture.onSuccess(server -> {
            logger.info("HTTP server started on port:{}", server.actualPort());
            startPromise.complete();
        });
        serverFuture.onFailure(err -> {
            startPromise.fail(err);
        });
    }

    /**
     * Router を構築し、各ルートにハンドラーを配線する。
     *
     * @param webAuthnService     WebAuthn サービス
     * @param sessionWebAPIClient セッション WebAPI クライアント
     * @return 設定済み Router
     */
    private Router buildRouter(WebAuthnService webAuthnService,
            SessionWebAPIClient sessionWebAPIClient) {
        Router router = Router.router(vertx);
        
        router.route().handler(BodyHandler.create());
        router.route().handler(new SessionWebAPIHandler(sessionWebAPIClient));

        router.post("/webauthn/register").handler(new PasskeyRegisterHandler(webAuthnService, sessionWebAPIClient));
        router.post("/webauthn/login").handler(new PasskeyLoginHandler(webAuthnService, sessionWebAPIClient));
        router.post("/webauthn/callback").handler(new PasskeyCallbackHandler(webAuthnService, sessionWebAPIClient));

        router.get("/api/user").handler(new UserInfoHandler());
        router.get("/*").handler(StaticHandler.create("webroot"));

        return router;
    }

    private WebAuthnService createWebAuthnService(String credentialsPath) {
        CredentialRepository credRepo = new JsonFileCredentialRepository(vertx, credentialsPath);
        return new WebAuthnService(
                vertx, credRepo, "localhost", "Passkey Demo", "http://localhost:8081");
    }

    /**
     * ファイル名を絶対パスに解決する。
     * カレントディレクトリに存在しない場合、app/ サブディレクトリも検索する
     * （プロジェクトルートから起動した場合のフォールバック）。
     *
     * @param filename 解決するファイル名
     * @return 解決後のパス文字列
     */
    private String resolveDataPath(String filename) {
        if (new File(filename).exists()) {
            return filename;
        }
        File inApp = new File("app", filename);
        if (inApp.exists()) {
            return inApp.getPath();
        }
        return filename;
    }
}

package org.example;

import io.vertx.core.Vertx;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class App {

    private static final Logger log = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) {
        Vertx vertx = Vertx.vertx();
        vertx.deployVerticle(new MainVerticle())
             .onSuccess(id -> log.info("MainVerticle deployed: {}", id))
             .onFailure(err -> {
                 log.error("Failed to deploy verticle", err);
                 vertx.close();
             });
    }
}

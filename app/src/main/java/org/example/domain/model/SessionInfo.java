package org.example.domain.model;

import io.vertx.core.json.JsonObject;

/**
 * セッション情報を表す値オブジェクト。
 *
 * @param userId        セッションに紐づくユーザーID
 * @param authStatus    認証済みかどうか
 * @param transactionId セッションのトランザクションID（UUID）
 */
public record SessionInfo(String userId, boolean authStatus, String transactionId) {

    /**
     * JsonObject からインスタンスを生成する。
     *
     * @param json セッション情報の JSON
     * @return SessionInfo インスタンス
     */
    public static SessionInfo fromJson(JsonObject json) {
        return new SessionInfo(
            json.getString("userId"),
            json.getBoolean("authStatus", false),
            json.getString("transactionId")
        );
    }

    /**
     * 認証済みかどうかを検証する。
     *
     * @throws IllegalStateException 未認証の場合
     */
    public void requireAuthenticated() {
        if (!authStatus) {
            throw new IllegalStateException("session is not authenticated");
        }
    }
}

package org.example.domain.repository;

import io.vertx.core.Future;
import io.vertx.ext.auth.webauthn4j.Authenticator;

import java.util.List;

/**
 * WebAuthn 認証器データの永続化インターフェース。
 */
public interface CredentialRepository {

    /**
     * userId または credId で認証器を検索する。
     *
     * @param userId ユーザーID（null 可）
     * @param credId クレデンシャルID（null 可）
     * @return 一致する認証器のリスト
     */
    Future<List<Authenticator>> find(String userId, String credId);

    /**
     * 新規クレデンシャルを保存する。既存の credId があれば置換する。
     *
     * @param authenticator 保存する認証器データ
     * @return 完了 Future
     */
    Future<Void> store(Authenticator authenticator);

    /**
     * 認証器のカウンターを更新する（リプレイ攻撃防止）。
     *
     * @param authenticator 更新する認証器データ
     * @return 完了 Future
     */
    Future<Void> updateCounter(Authenticator authenticator);
}

package org.example.domain.repository;

import io.vertx.core.Future;
import org.example.domain.model.CredentialRecord;

import java.util.List;

/**
 * WebAuthn クレデンシャルの永続化インターフェース。
 */
public interface CredentialRepository {

    /**
     * userId または credentialId でクレデンシャルを検索する。
     *
     * @param userId       ユーザーID（null 可）
     * @param credentialId クレデンシャルID（null 可）
     * @return 一致するクレデンシャルのリスト
     */
    Future<List<CredentialRecord>> find(String userId, String credentialId);

    /**
     * クレデンシャルを保存する。既存の credentialId があれば置換する。
     *
     * @param record 保存するクレデンシャル
     * @return 完了 Future
     */
    Future<Void> store(CredentialRecord record);

    /**
     * 署名カウンターを更新する（リプレイ攻撃防止）。
     *
     * @param credentialId 更新するクレデンシャルID
     * @param newCount     新しいカウンター値
     * @return 完了 Future
     */
    Future<Void> updateCounter(String credentialId, long newCount);
}

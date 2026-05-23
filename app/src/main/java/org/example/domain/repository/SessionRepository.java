package org.example.domain.repository;

import io.vertx.core.Future;
import org.example.domain.model.SessionInfo;

/**
 * セッション情報取得インターフェース。
 * 本番環境ではセッション WebAPI を呼ぶ実装に差し替える。
 */
public interface SessionRepository {

    /**
     * sessionId に対応するセッション情報を取得する。
     *
     * @param sessionId セッションID（UUID）
     * @return セッション情報。存在しない場合は失敗 Future
     */
    Future<SessionInfo> findSession(String sessionId);
}

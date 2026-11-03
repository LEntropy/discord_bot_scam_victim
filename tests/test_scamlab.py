"""scamlab 핵심 동작 검증.

핵심 주장:
1. 방어가 없으면 계정 탈취 → 모든 채널 스캠 도배가 성공한다.
2. 방어를 켜면 스캠이 0건 도달하고 경보가 발생한다.
3. 각 방어가 의도한 공격 단계를 실제로 차단한다.
"""

import pytest

from scamlab import MockDiscord, SecurityPolicy, SecurityBlocked
from scamlab import attacks
from scamlab.scenarios import build_world, run_chain, compare
from scamlab.security import (
    ScamContentScanner,
    BroadcastAnomalyDetector,
    TokenBinding,
    ScopeMinimizer,
    BotPermissionAuditor,
    RateLimiter,
)
from scamlab.platform import Bot


# --------------------------------------------------------------------------- #
# 엔드투엔드: 취약 vs 방어
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("entry", ["token_grabber", "qr_login", "oauth_phish"])
def test_insecure_chain_floods_all_channels(entry):
    res = run_chain(None, "insecure", entry=entry)
    # 서버 4 * 채널 5 = 20개 채널 전부 도배
    assert res.spam_delivered == 20
    assert res.alerts == 0


@pytest.mark.parametrize("entry", ["token_grabber", "qr_login", "oauth_phish"])
def test_secure_chain_blocks_everything(entry):
    res = run_chain(SecurityPolicy(), "secure", entry=entry)
    assert res.spam_delivered == 0
    assert res.alerts >= 1


def test_compare_helper():
    insecure, secure = compare("token_grabber")
    assert insecure.spam_delivered == 20
    assert secure.spam_delivered == 0


# --------------------------------------------------------------------------- #
# 개별 방어 단위 테스트
# --------------------------------------------------------------------------- #
def test_content_scanner_flags_btc_scam():
    s = ScamContentScanner()
    score, hits = s.score(attacks.SCAM_MESSAGE)
    assert score >= 2
    assert "scam-lure-phrase" in hits


def test_content_scanner_ignores_normal_chat():
    s = ScamContentScanner()
    score, _ = s.score("점심 뭐 먹을까? 회의는 3시야")
    assert score == 0


def test_token_binding_blocks_unknown_device():
    tb = TokenBinding()

    class U:
        known_fingerprints = {"alice-desktop"}

    tb.check(U(), "alice-desktop")  # 정상 기기는 통과
    with pytest.raises(SecurityBlocked):
        tb.check(U(), "attacker-pc")  # 낯선 기기는 차단


def test_broadcast_anomaly_blocks_fanout():
    d = BroadcastAnomalyDetector(fanout_channels=3, window_s=30)
    d.check("u", "c1", "buy btc now")
    d.check("u", "c2", "buy btc now")
    with pytest.raises(SecurityBlocked):
        d.check("u", "c3", "buy btc now")  # 3번째 채널에서 차단


def test_rate_limiter():
    rl = RateLimiter(max_msgs=2, window_s=100)
    rl.check("u")
    rl.check("u")
    with pytest.raises(SecurityBlocked):
        rl.check("u")


def test_scope_minimizer_blocks_dangerous_oauth():
    sm = ScopeMinimizer()

    class App:
        name = "evil"
        requested_scopes = ["identify", "guilds.join"]

    with pytest.raises(SecurityBlocked):
        sm.check(App())


def test_bot_auditor_blocks_admin():
    ba = BotPermissionAuditor()
    with pytest.raises(SecurityBlocked):
        ba.check(Bot(id="b", name="evil", permissions={"ADMINISTRATOR"}))


# --------------------------------------------------------------------------- #
# 진입 단계가 방어로 막히는지
# --------------------------------------------------------------------------- #
def test_token_grabber_then_blocked_at_auth():
    # 토큰 자체는 금고에서 훔칠 수 있지만(멀웨어가 파일을 읽는 것은 막기 어렵다),
    # 토큰 바인딩이 켜져 있으면 '낯선 기기에서의 사용'이 차단된다.
    p, victim, victim_fp = build_world(SecurityPolicy())
    r = attacks.token_grabber_sim(p, "attacker-pc")
    assert r.succeeded  # 파일 탈취 자체는 성공
    spam = attacks.mass_spam(p, r.artifacts["token"], "attacker-pc")
    assert spam.succeeded is False  # 사용 단계에서 차단
    assert p.alerts()


def test_oauth_phish_blocked_by_scope_policy():
    p, victim, victim_fp = build_world(SecurityPolicy())
    r = attacks.oauth_phish_sim(p, victim.token, victim_fp)
    assert r.succeeded is False


def test_webhook_scam_blocked():
    p, victim, victim_fp = build_world(SecurityPolicy())
    ch = next(iter(p.channels.values()))
    wh = p.create_webhook(victim.token, ch.id, victim_fp)
    with pytest.raises(SecurityBlocked):
        p.execute_webhook(wh.id, wh.token, attacks.SCAM_MESSAGE, is_image=True)

"""scenarios.py — 공격 체인 전체를 '방어 없음 vs 방어 있음'으로 돌려보는 시나리오.

데모와 테스트가 공유하는 진실의 원천(single source of truth).
"""

from __future__ import annotations

from dataclasses import dataclass

from . import attacks
from .platform import MockDiscord
from .security import SecurityPolicy


@dataclass
class ScenarioResult:
    label: str
    spam_delivered: int   # 실제로 채널에 도달한 스캠 메시지 수
    spam_blocked: int     # 차단된 스캠 시도 수
    alerts: int           # 발생한 보안 경보 수
    grabber_ok: bool
    notes: list[str]


def build_world(policy: SecurityPolicy | None) -> tuple[MockDiscord, object, str]:
    """피해자 1명 + 서버 4개 + 서버당 채널 5개 규모의 작은 세계를 만든다.

    피해자는 데스크톱에서 로그인한 상태(=금고에 토큰 존재).
    반환: (platform, victim, victim_fingerprint)
    """
    p = MockDiscord(policy=policy)
    victim = p.register_user("alice", "alice@example.com", "pw", mfa=True)
    victim_fp = "alice-desktop"
    # 데스크톱 로그인 → 토큰이 금고에 저장됨
    p.login("alice", "pw", fingerprint=victim_fp, mfa_code="123456")

    for gi in range(4):
        g = p.create_guild(victim, f"server-{gi}")
        for ci in range(5):
            p.create_channel(g, f"channel-{gi}-{ci}")
    return p, victim, victim_fp


def run_chain(policy: SecurityPolicy | None, label: str,
              entry: str = "token_grabber") -> ScenarioResult:
    """진입(entry) → 대량 살포(impact) 체인을 1회 실행.

    entry: "token_grabber" | "qr_login" | "oauth_phish"
    """
    p, victim, victim_fp = build_world(policy)
    notes: list[str] = []
    attacker_fp = "attacker-pc"
    grabber_ok = False
    stolen_token = victim.token  # qr/oauth 경로에서는 토큰 동치물을 사용

    if entry == "token_grabber":
        r = attacks.token_grabber_sim(p, attacker_fp)
        grabber_ok = r.succeeded
        notes.append(f"[진입] {r.detail}")
        if r.succeeded:
            stolen_token = r.artifacts["token"]
    elif entry == "qr_login":
        r = attacks.qr_login_sim(p, victim.token, victim_fp, attacker_fp)
        grabber_ok = r.succeeded
        notes.append(f"[진입] {r.detail}")
        stolen_token = r.artifacts["token"]
    elif entry == "oauth_phish":
        r = attacks.oauth_phish_sim(p, victim.token, victim_fp)
        grabber_ok = r.succeeded
        notes.append(f"[진입] {r.detail}")

    # 영향: 탈취 토큰으로 모든 채널에 스캠 살포
    spam = attacks.mass_spam(p, stolen_token, attacker_fp)
    notes.append(f"[영향] {spam.detail}")

    delivered = p.count_messages(lambda m: m.author_id == victim.id and m.is_image)
    return ScenarioResult(
        label=label,
        spam_delivered=delivered,
        spam_blocked=spam.artifacts.get("blocked", 0),
        alerts=len(p.alerts()),
        grabber_ok=grabber_ok,
        notes=notes,
    )


def compare(entry: str = "token_grabber") -> tuple[ScenarioResult, ScenarioResult]:
    """방어 없음 vs 전체 방어 결과를 나란히 반환."""
    insecure = run_chain(None, "방어 없음(취약)", entry=entry)
    secure = run_chain(SecurityPolicy(), "방어 적용", entry=entry)
    return insecure, secure

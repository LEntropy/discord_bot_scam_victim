"""attacks.py — 계정 탈취 스캠 체인의 각 단계를 '안전하게' 재현.

⚠️ 중요: 이 코드는 실제 디스코드/실제 기기를 공격하지 않는다.
모든 함수는 scamlab.MockDiscord 인스턴스에만 작용한다. 실제 토큰 추출/복호화,
실제 웹훅 탈취 같은 무기화된 기능은 의도적으로 구현하지 않았다 (개념 시연용).

재현하는 단계
-------------
1) 진입(initial access):
   - token_grabber_sim   : 데스크톱 금고에서 토큰 탈취 (멀웨어/악성 npm 패키지 류)
   - oauth_phish_sim     : 가짜 'verify' 봇 OAuth 인가 유도
   - qr_login_sim        : 가짜 인증 QR 스캔 → 원격 로그인 탈취
2) 영향(impact):
   - mass_spam           : 탈취 토큰으로 모든 서버/채널에 비트코인 스캠 살포
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .platform import MockDiscord, SecurityBlocked

# 데모에서 사용할 전형적인 비트코인 스캠 메시지 (이미지 캡션 형태)
SCAM_MESSAGE = (
    "🎉 ELON x DISCORD CRYPTO GIVEAWAY 🎉\n"
    "Send 0.1 BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh "
    "and receive DOUBLE back! Limited time, first 500 users only. "
    "Claim now: https://discord-nitro.claim-btc.example"
)


@dataclass
class AttackReport:
    """공격 시도 결과 요약."""

    stage: str
    succeeded: bool
    detail: str
    artifacts: dict = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# 1) 진입 단계
# --------------------------------------------------------------------------- #
def token_grabber_sim(platform: MockDiscord, attacker_fingerprint: str = "attacker-pc") -> AttackReport:
    """토큰 그래버 멀웨어를 흉내 낸다.

    실제 멀웨어: LevelDB(.ldb/.log)에서 DPAPI 암호화 토큰을 읽어 복호화 후 웹훅으로 유출.
    여기서는 MockDiscord.vault(단순화된 금고)에서 토큰을 '읽어' 공격자에게 넘긴다.
    """
    stolen = platform.vault.read_all()  # {fingerprint: token}
    if not stolen:
        return AttackReport("token_grabber", False, "금고가 비어 있음(데스크톱 로그인 없음)")
    # 공격자는 첫 번째(혹은 모든) 토큰을 확보. 공격자 기기로 가져간다.
    victim_fp, token = next(iter(stolen.items()))
    return AttackReport(
        "token_grabber", True,
        f"데스크톱 금고에서 토큰 탈취 (원 기기={victim_fp})",
        artifacts={"token": token, "attacker_fingerprint": attacker_fingerprint},
    )


def oauth_phish_sim(platform: MockDiscord, victim_token: str, victim_fp: str,
                    app_name: str = "Safeguard Verify") -> AttackReport:
    """가짜 'verify' 봇의 OAuth 인가 유도(피싱)를 흉내 낸다.

    악성 앱은 위험 스코프(messages.write, guilds.join 등)를 요구한다.
    유저가 승인하면 앱은 계정에 준하는 접근권을 얻는다.
    """
    app = platform.register_oauth_app(
        name=app_name,
        redirect_uri="https://verify.example/callback",
        scopes=["identify", "guilds", "guilds.join", "messages.write"],
    )
    try:
        grant = platform.oauth_authorize(victim_token, app.id, victim_fp)
    except SecurityBlocked as e:
        return AttackReport("oauth_phish", False, f"인가 거부됨: {e}")
    return AttackReport(
        "oauth_phish", grant["can_act_as_user"],
        f"악성 앱 '{app_name}' 인가 성공, 계정대행 가능={grant['can_act_as_user']}",
        artifacts={"grant": grant},
    )


def qr_login_sim(platform: MockDiscord, victim_token: str, victim_fp: str,
                 attacker_fingerprint: str = "attacker-pc") -> AttackReport:
    """가짜 인증 QR 스캔으로 원격 로그인 세션을 탈취하는 흐름을 흉내 낸다.

    실제: 공격자가 discord.com 원격인증 소켓의 QR을 받아 '인증 봇' QR인 척 배포.
    피해자가 스캔/승인하면 공격자 기기가 그 계정 토큰을 받는다.
    여기서는 피해자가 '승인'하면 공격자 지문이 동일 토큰을 쓰게 된다.
    """
    # 스캔/승인 = 공격자 기기가 토큰을 손에 넣는 것과 동치
    return AttackReport(
        "qr_login", True,
        "피해자가 가짜 QR을 스캔/승인 → 공격자 기기가 계정 토큰 확보",
        artifacts={"token": victim_token, "attacker_fingerprint": attacker_fingerprint},
    )


# --------------------------------------------------------------------------- #
# 2) 영향 단계
# --------------------------------------------------------------------------- #
def mass_spam(platform: MockDiscord, stolen_token: str, attacker_fingerprint: str,
              message: str = SCAM_MESSAGE) -> AttackReport:
    """탈취한 토큰으로 계정이 속한 모든 서버의 모든 채널에 스캠을 살포한다.

    이것이 피해자 친구/서버가 보게 되는 바로 그 도배 메시지다.
    """
    sent, blocked = 0, 0
    block_reasons: dict[str, int] = {}
    try:
        channels = platform.list_accessible_channels(stolen_token, attacker_fingerprint)
    except SecurityBlocked as e:
        return AttackReport(
            "mass_spam", False,
            f"채널 열람 단계에서 차단됨: {e.reason}",
            artifacts={"sent": 0, "blocked_at": "enumerate", "reason": e.reason},
        )

    for ch in channels:
        try:
            platform.send_message(stolen_token, ch.id, message,
                                  fingerprint=attacker_fingerprint, is_image=True)
            sent += 1
        except SecurityBlocked as e:
            blocked += 1
            block_reasons[e.reason] = block_reasons.get(e.reason, 0) + 1

    return AttackReport(
        "mass_spam", sent > 0,
        f"스캠 전송 성공 {sent}건 / 차단 {blocked}건",
        artifacts={"sent": sent, "blocked": blocked, "block_reasons": block_reasons},
    )

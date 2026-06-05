"""security.py — 계정 탈취 스캠 체인을 끊는 방어 계층.

SecurityPolicy 하나에 여러 탐지기를 조립해 넣고, MockDiscord 의 민감 동작 훅에서
호출한다. 각 방어는 디스코드/일반 SaaS에서 실제로 쓰이는 완화책에 대응한다.

방어 ↔ 공격 매핑
----------------
- TokenBinding          ↔ 토큰 그래버/QR 탈취 (낯선 기기에서의 토큰 사용 차단)
- RateLimiter           ↔ 대량 스팸 (초당 메시지 폭주 차단)
- BroadcastAnomaly      ↔ "모든 채널에 같은 글" 패턴 (대량 전파 차단·격리)
- ScamContentScanner    ↔ 비트코인 스캠 문구/주소/미끼 링크 탐지
- ScopeMinimizer        ↔ OAuth 과다 스코프 인가 차단
- BotPermissionAuditor  ↔ 봇 Administrator 등 과도 권한 차단
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque

from .platform import SecurityBlocked


# --------------------------------------------------------------------------- #
# 개별 탐지기
# --------------------------------------------------------------------------- #
class ScamContentScanner:
    """암호화폐 스캠 메시지의 전형적 신호를 휴리스틱으로 탐지."""

    # 비트코인/이더리움 주소 비슷한 패턴
    _BTC = re.compile(r"\b(bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
    _ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
    # 전형적 미끼 문구 (영문/한글)
    _LURES = [
        r"double your (btc|bitcoin|eth|crypto)",
        r"(free|claim).{0,12}(nitro|airdrop|giveaway)",
        r"send .{0,10}(btc|eth).{0,20}(receive|get).{0,10}back",
        r"limited time", r"act now", r"first \d+ users",
        r"무료.{0,6}(니트로|에어드랍|코인)", r"두\s?배", r"즉시.{0,6}지급",
        r"선착순", r"지금.{0,4}참여",
    ]
    _LURE_RE = re.compile("|".join(_LURES), re.IGNORECASE)
    # 미끼 링크 (단축/메신저/사칭 도메인)
    _BAD_LINK = re.compile(r"(t\.me/|bit\.ly/|discordgift|discord-nitro|steamcommunity\.[a-z]+\.ru|claim-)", re.I)

    def score(self, content: str) -> tuple[int, list[str]]:
        hits: list[str] = []
        if self._BTC.search(content):
            hits.append("crypto-address(BTC)")
        if self._ETH.search(content):
            hits.append("crypto-address(ETH)")
        if self._LURE_RE.search(content):
            hits.append("scam-lure-phrase")
        if self._BAD_LINK.search(content):
            hits.append("suspicious-link")
        return len(hits), hits


class RateLimiter:
    """유저별 토큰 버킷. 짧은 시간에 너무 많은 메시지를 막는다."""

    def __init__(self, max_msgs: int = 5, window_s: float = 10.0):
        self.max_msgs = max_msgs
        self.window_s = window_s
        self._events: dict[str, deque] = defaultdict(deque)

    def check(self, user_id: str) -> None:
        now = time.time()
        q = self._events[user_id]
        while q and now - q[0] > self.window_s:
            q.popleft()
        if len(q) >= self.max_msgs:
            raise SecurityBlocked(
                "rate_limited",
                f"{self.window_s:.0f}초 내 {self.max_msgs}개 초과 — 자동화/스팸 의심",
            )
        q.append(now)


class BroadcastAnomalyDetector:
    """'동일/유사 콘텐츠를 여러 채널·여러 길드에 살포'하는 패턴 탐지.

    스캠 봇의 가장 뚜렷한 특징. 사람은 같은 글을 수십 개 채널에 도배하지 않는다.
    """

    def __init__(self, fanout_channels: int = 3, window_s: float = 30.0):
        self.fanout_channels = fanout_channels
        self.window_s = window_s
        # user_id -> content_hash -> deque[(ts, channel_id)]
        self._seen: dict[str, dict[int, deque]] = defaultdict(lambda: defaultdict(deque))

    def check(self, user_id: str, channel_id: str, content: str) -> None:
        now = time.time()
        h = hash(re.sub(r"\s+", " ", content.strip().lower()))
        q = self._seen[user_id][h]
        while q and now - q[0][0] > self.window_s:
            q.popleft()
        channels = {cid for _, cid in q}
        channels.add(channel_id)
        q.append((now, channel_id))
        if len(channels) >= self.fanout_channels:
            raise SecurityBlocked(
                "broadcast_anomaly",
                f"동일 콘텐츠가 {len(channels)}개 채널에 {self.window_s:.0f}초 내 전파 — 대량 살포 차단",
            )


class TokenBinding:
    """토큰을 발급 시점의 기기 지문에 묶는다.

    디스코드 토큰 탈취의 본질은 '토큰이 기기와 무관하게 어디서든 통한다'는 것.
    낯선 지문에서 토큰을 쓰면 차단하고 재인증(2FA)을 강제한다.
    """

    def check(self, user, fingerprint: str) -> None:
        if fingerprint not in user.known_fingerprints:
            raise SecurityBlocked(
                "untrusted_device",
                f"등록되지 않은 기기({fingerprint})에서 토큰 사용 — 재인증 필요",
            )


class ScopeMinimizer:
    """OAuth 앱이 위험 스코프를 요구하면 인가를 막거나 경고."""

    DANGEROUS = {"messages.write", "guilds.join", "bot", "webhook.incoming"}

    def check(self, app) -> None:
        bad = self.DANGEROUS.intersection(app.requested_scopes)
        if bad:
            raise SecurityBlocked(
                "excessive_oauth_scope",
                f"앱 '{app.name}' 이 위험 스코프 {sorted(bad)} 요구 — 인가 거부",
            )


class BotPermissionAuditor:
    """봇에 부여되는 권한을 감사. Administrator/위험 권한을 막는다."""

    DANGEROUS = {"ADMINISTRATOR", "MANAGE_WEBHOOKS", "MENTION_EVERYONE"}

    def check(self, bot) -> None:
        bad = self.DANGEROUS.intersection(bot.permissions)
        if bad:
            raise SecurityBlocked(
                "excessive_bot_permission",
                f"봇 '{bot.name}' 에 과도한 권한 {sorted(bad)} — 최소권한 위반",
            )


# --------------------------------------------------------------------------- #
# 통합 정책
# --------------------------------------------------------------------------- #
class SecurityPolicy:
    """탐지기들을 묶어 MockDiscord 의 훅에 응답한다.

    각 방어는 생성자 인자로 개별 on/off 가능 (어떤 방어가 어떤 공격을 막는지
    실험·비교하기 좋게).
    """

    def __init__(
        self,
        token_binding: bool = True,
        rate_limit: bool = True,
        broadcast_detect: bool = True,
        content_scan: bool = True,
        scope_minimize: bool = True,
        bot_audit: bool = True,
        content_block_threshold: int = 2,
    ):
        self.token_binding = TokenBinding() if token_binding else None
        self.rate_limiter = RateLimiter() if rate_limit else None
        self.broadcast = BroadcastAnomalyDetector() if broadcast_detect else None
        self.scanner = ScamContentScanner() if content_scan else None
        self.scope_min = ScopeMinimizer() if scope_minimize else None
        self.bot_auditor = BotPermissionAuditor() if bot_audit else None
        self.content_block_threshold = content_block_threshold

    # ---- MockDiscord 훅 ----------------------------------------------------
    def on_authenticate(self, platform, user, fingerprint, action):
        if self.token_binding:
            try:
                self.token_binding.check(user, fingerprint)
            except SecurityBlocked as e:
                platform._log("ALERT", user.id,
                              f"토큰 바인딩 차단({action}): {e.detail}", severity="alert")
                raise

    def on_send_message(self, platform, user, channel, content, is_image):
        if self.scanner:
            score, hits = self.scanner.score(content)
            if score >= self.content_block_threshold:
                platform._log("ALERT", user.id,
                              f"스캠 콘텐츠 차단(score={score}, {hits})", severity="alert")
                raise SecurityBlocked("scam_content", f"스캠 신호 {hits}")
        if self.rate_limiter:
            try:
                self.rate_limiter.check(user.id)
            except SecurityBlocked as e:
                platform._log("ALERT", user.id, f"레이트리밋: {e.detail}", severity="alert")
                raise
        if self.broadcast:
            try:
                self.broadcast.check(user.id, channel.id, content)
            except SecurityBlocked as e:
                platform._log("ALERT", user.id, f"대량전파 차단: {e.detail}", severity="alert")
                raise

    def on_oauth_authorize(self, platform, user, app):
        if self.scope_min:
            try:
                self.scope_min.check(app)
            except SecurityBlocked as e:
                platform._log("ALERT", user.id, f"OAuth 스코프 차단: {e.detail}", severity="alert")
                raise

    def on_add_bot(self, platform, guild, bot):
        if self.bot_auditor:
            try:
                self.bot_auditor.check(bot)
            except SecurityBlocked as e:
                platform._log("ALERT", guild.owner_id, f"봇 권한 차단: {e.detail}", severity="alert")
                raise

    def on_webhook_execute(self, platform, webhook, content, is_image):
        if self.scanner:
            score, hits = self.scanner.score(content)
            if score >= self.content_block_threshold:
                platform._log("ALERT", f"webhook:{webhook.id}",
                              f"웹훅 스캠 콘텐츠 차단({hits})", severity="alert")
                raise SecurityBlocked("scam_content", f"웹훅 스캠 신호 {hits}")

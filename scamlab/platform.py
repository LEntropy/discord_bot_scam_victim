"""MockDiscord — 디스코드를 본뜬 최소 모의 플랫폼 (교육용).

실제 디스코드 API를 호출하지 않으며, 모든 상태는 메모리에 존재합니다.
디스코드의 핵심 보안 모델 중 이 데모와 관련된 부분만 재현합니다.

재현하는 디스코드 개념
----------------------
- **유저 토큰(user token)**: 디스코드에서 계정 인증의 사실상 전부. 토큰만 있으면
  비밀번호/2FA 없이도 그 계정으로 무엇이든 할 수 있다. (← 스캠의 핵심)
- **길드(guild)/채널(channel)/메시지(message)**: 서버와 채널, 그리고 메시지.
- **OAuth2 앱**: "verify 버튼" 류의 외부 앱 인가 흐름.
- **봇 + 권한 비트**: 봇을 서버에 추가할 때 부여하는 권한.
- **웹훅(webhook)**: 채널에 메시지를 쏠 수 있는 URL.
- **데스크톱 로컬 스토리지 금고**: 실제 디스코드 데스크톱 앱은 토큰을 LevelDB에
  보관(DPAPI로 암호화)한다. 여기서는 그 "금고"를 단순화해 재현한다 (실데이터 추출 X).

보안 정책 훅
------------
민감한 동작마다 ``self.policy`` (SecurityPolicy | None) 의 콜백을 호출한다.
정책이 None이면 디스코드의 "취약한" 기본 동작을 그대로 따른다.
정책이 차단하면 ``SecurityBlocked`` 예외가 발생한다.
"""

from __future__ import annotations

import base64
import itertools
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


# --------------------------------------------------------------------------- #
# 예외 / 이벤트
# --------------------------------------------------------------------------- #
class SecurityBlocked(Exception):
    """방어 정책이 어떤 동작을 차단했을 때 발생."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass
class AuditEvent:
    """플랫폼에서 일어난 일을 기록하는 감사 로그 한 줄."""

    ts: float
    kind: str          # 예: "login", "send_message", "oauth_authorize", "ALERT"
    actor: str         # user id 또는 "system"
    detail: str
    severity: str = "info"  # info | warn | alert


# --------------------------------------------------------------------------- #
# 도메인 모델
# --------------------------------------------------------------------------- #
@dataclass
class User:
    id: str
    username: str
    email: str
    password: str
    mfa_enabled: bool = False
    token: str = ""
    # 토큰을 사용한 적 있는 기기 지문 집합 (토큰 바인딩 방어에 사용)
    known_fingerprints: set = field(default_factory=set)


@dataclass
class Message:
    id: str
    channel_id: str
    author_id: str
    content: str
    ts: float
    is_image: bool = False


@dataclass
class Channel:
    id: str
    guild_id: str
    name: str
    messages: list = field(default_factory=list)


@dataclass
class Guild:
    id: str
    name: str
    owner_id: str
    channel_ids: list = field(default_factory=list)
    member_ids: list = field(default_factory=list)
    bot_ids: list = field(default_factory=list)


@dataclass
class OAuthApp:
    id: str
    name: str
    redirect_uri: str
    # 앱이 요청하는 OAuth 스코프 (예: identify, guilds, guilds.join, bot ...)
    requested_scopes: list = field(default_factory=list)


@dataclass
class Bot:
    id: str
    name: str
    # 디스코드 권한 비트마스크를 흉내 낸 권한 이름 집합
    permissions: set = field(default_factory=set)


@dataclass
class Webhook:
    id: str
    channel_id: str
    token: str  # 이 토큰을 아는 사람은 누구나 채널에 글을 쓸 수 있다


# --------------------------------------------------------------------------- #
# 데스크톱 토큰 금고 (LevelDB + DPAPI 의 단순화 모델)
# --------------------------------------------------------------------------- #
class LocalStorageVault:
    """디스코드 데스크톱 앱의 토큰 저장소를 흉내 낸 것.

    실제로는 ``%AppData%/discord/Local Storage/leveldb`` 안의 .ldb/.log 파일에
    DPAPI로 암호화된 토큰이 들어 있다. 토큰 그래버 멀웨어는 이 파일을 읽고
    DPAPI로 복호화해 토큰을 빼낸다.

    여기서는 "기기별로 base64 인코딩된 토큰"이라는 아주 단순한 형태로 재현한다.
    (실제 추출/복호화 코드가 아니라 개념 시연용)
    """

    def __init__(self):
        # device_fingerprint -> "encrypted" token blob
        self._blobs: dict[str, str] = {}

    def store(self, fingerprint: str, token: str) -> None:
        # DPAPI 암호화를 base64 로 흉내 냄
        self._blobs[fingerprint] = base64.b64encode(token.encode()).decode()

    def read_all(self) -> dict[str, str]:
        """그래버 관점: 금고 안의 모든 (지문, 복호화된 토큰)을 반환."""
        out = {}
        for fp, blob in self._blobs.items():
            out[fp] = base64.b64decode(blob.encode()).decode()
        return out


# --------------------------------------------------------------------------- #
# 모의 플랫폼
# --------------------------------------------------------------------------- #
class MockDiscord:
    def __init__(self, policy: Optional["object"] = None):
        self.policy = policy  # SecurityPolicy | None
        self.users: dict[str, User] = {}
        self.guilds: dict[str, Guild] = {}
        self.channels: dict[str, Channel] = {}
        self.oauth_apps: dict[str, OAuthApp] = {}
        self.bots: dict[str, Bot] = {}
        self.webhooks: dict[str, Webhook] = {}
        self.audit_log: list[AuditEvent] = []
        # 토큰 -> user id (디스코드는 토큰 하나로 모든 인증을 처리)
        self._token_index: dict[str, str] = {}
        # 데스크톱 기기별 토큰 금고
        self.vault = LocalStorageVault()
        self._ids = itertools.count(1)

    # ---- 내부 헬퍼 ---------------------------------------------------------
    def _new_id(self, prefix: str) -> str:
        return f"{prefix}_{next(self._ids)}"

    def _log(self, kind: str, actor: str, detail: str, severity: str = "info") -> None:
        self.audit_log.append(
            AuditEvent(ts=time.time(), kind=kind, actor=actor, detail=detail, severity=severity)
        )

    def alerts(self) -> list[AuditEvent]:
        return [e for e in self.audit_log if e.severity == "alert"]

    # ---- 셋업 API ----------------------------------------------------------
    def register_user(self, username: str, email: str, password: str, mfa: bool = False) -> User:
        uid = self._new_id("user")
        token = self._mint_token(uid)
        user = User(id=uid, username=username, email=email, password=password,
                    mfa_enabled=mfa, token=token)
        self.users[uid] = user
        self._token_index[token] = uid
        self._log("register", uid, f"user '{username}' created")
        return user

    def _mint_token(self, uid: str) -> str:
        # 디스코드 토큰처럼 추측 불가능한 비밀 문자열
        return f"{base64.b64encode(uid.encode()).decode().rstrip('=')}.{secrets.token_urlsafe(24)}"

    def create_guild(self, owner: User, name: str) -> Guild:
        gid = self._new_id("guild")
        g = Guild(id=gid, name=name, owner_id=owner.id, member_ids=[owner.id])
        self.guilds[gid] = g
        self._log("create_guild", owner.id, f"guild '{name}'")
        return g

    def create_channel(self, guild: Guild, name: str) -> Channel:
        cid = self._new_id("chan")
        c = Channel(id=cid, guild_id=guild.id, name=name)
        self.channels[cid] = c
        guild.channel_ids.append(cid)
        return c

    # ---- 인증 핵심 ---------------------------------------------------------
    def login(self, username: str, password: str, fingerprint: str, mfa_code: str = "") -> str:
        """정상 로그인. 토큰을 발급하고 데스크톱 금고에 저장한다."""
        user = next((u for u in self.users.values() if u.username == username), None)
        if not user or user.password != password:
            raise SecurityBlocked("auth_failed", "잘못된 자격증명")
        if user.mfa_enabled and mfa_code != "123456":  # 데모용 고정 OTP
            raise SecurityBlocked("auth_failed", "MFA 코드 불일치")
        user.known_fingerprints.add(fingerprint)
        self.vault.store(fingerprint, user.token)
        self._log("login", user.id, f"from device {fingerprint}")
        return user.token

    def authenticate(self, token: str, fingerprint: str, action: str = "") -> User:
        """토큰으로 행위자를 인증한다. 모든 민감 동작의 관문.

        디스코드의 취약점 본질: 토큰만 맞으면 그냥 통과된다(정책 없을 때).
        토큰 바인딩 방어가 켜져 있으면 '낯선 기기'를 여기서 막는다.
        """
        uid = self._token_index.get(token)
        if uid is None:
            raise SecurityBlocked("invalid_token", "알 수 없는 토큰")
        user = self.users[uid]
        if self.policy:
            # 방어 훅: 새 기기에서의 토큰 사용 등을 검사
            self.policy.on_authenticate(self, user, fingerprint, action)
        return user

    # ---- 메시지 ------------------------------------------------------------
    def send_message(self, token: str, channel_id: str, content: str,
                     fingerprint: str, is_image: bool = False) -> Message:
        user = self.authenticate(token, fingerprint, action="send_message")
        channel = self.channels[channel_id]
        if self.policy:
            # 방어 훅: 레이트리밋 / 대량전파 탐지 / 스캠 콘텐츠 스캔
            self.policy.on_send_message(self, user, channel, content, is_image)
        msg = Message(id=self._new_id("msg"), channel_id=channel_id,
                      author_id=user.id, content=content, ts=time.time(), is_image=is_image)
        channel.messages.append(msg)
        return msg

    def list_accessible_channels(self, token: str, fingerprint: str) -> list[Channel]:
        """이 토큰(=계정)이 글을 쓸 수 있는 모든 채널.

        스팸 봇이 '모든 서버의 모든 채널'을 훑을 때 쓰는 바로 그 능력.
        """
        user = self.authenticate(token, fingerprint, action="enumerate")
        out = []
        for g in self.guilds.values():
            if user.id in g.member_ids:
                out.extend(self.channels[cid] for cid in g.channel_ids)
        return out

    # ---- OAuth2 ------------------------------------------------------------
    def register_oauth_app(self, name: str, redirect_uri: str, scopes: list[str]) -> OAuthApp:
        app = OAuthApp(id=self._new_id("app"), name=name,
                       redirect_uri=redirect_uri, requested_scopes=list(scopes))
        self.oauth_apps[app.id] = app
        return app

    def oauth_authorize(self, token: str, app_id: str, fingerprint: str) -> dict:
        """유저가 'verify' 버튼을 눌러 외부 앱을 인가하는 흐름.

        취약 시나리오: 앱이 광범위한 스코프(guilds.join, messages 등)를 요구하고
        유저가 무심코 승인 → 앱이 계정에 준하는 접근권을 얻는다.
        """
        user = self.authenticate(token, fingerprint, action="oauth_authorize")
        app = self.oauth_apps[app_id]
        if self.policy:
            self.policy.on_oauth_authorize(self, user, app)
        # 단순화: 승인되면 앱에 access grant(=토큰 유사물) 발급
        grant = {
            "app_id": app.id,
            "user_id": user.id,
            "scopes": app.requested_scopes,
            "access_token": secrets.token_urlsafe(24),
            # 위험 스코프가 포함되면 앱은 사실상 계정 토큰처럼 행동 가능
            "can_act_as_user": any(s in app.requested_scopes
                                   for s in ("messages.write", "guilds.join", "bot")),
        }
        self._log("oauth_authorize", user.id,
                  f"app '{app.name}' scopes={app.requested_scopes}",
                  severity="warn" if grant["can_act_as_user"] else "info")
        return grant

    # ---- 봇 / 권한 ---------------------------------------------------------
    def add_bot_to_guild(self, owner: User, guild: Guild, bot: Bot) -> None:
        """봇을 서버에 추가하며 권한을 부여한다.

        취약 시나리오: 관리자가 봇에 Administrator 권한을 통째로 준다 →
        봇이 모든 채널에 글을 쓸 수 있게 된다.
        """
        self.bots[bot.id] = bot
        if self.policy:
            self.policy.on_add_bot(self, guild, bot)
        guild.bot_ids.append(bot.id)
        self._log("add_bot", owner.id,
                  f"bot '{bot.name}' perms={sorted(bot.permissions)} -> guild '{guild.name}'",
                  severity="warn" if "ADMINISTRATOR" in bot.permissions else "info")

    # ---- 웹훅 --------------------------------------------------------------
    def create_webhook(self, token: str, channel_id: str, fingerprint: str) -> Webhook:
        self.authenticate(token, fingerprint, action="create_webhook")
        wh = Webhook(id=self._new_id("wh"), channel_id=channel_id,
                     token=secrets.token_urlsafe(16))
        self.webhooks[wh.id] = wh
        return wh

    def execute_webhook(self, webhook_id: str, webhook_token: str,
                        content: str, is_image: bool = False) -> Message:
        """웹훅 실행. 웹훅 URL(=id+token)만 알면 인증 없이 글을 쓴다.

        이것이 웹훅이 유출되면 위험한 이유다. 방어 정책은 콘텐츠 스캔을 적용.
        """
        wh = self.webhooks[webhook_id]
        if wh.token != webhook_token:
            raise SecurityBlocked("invalid_webhook", "웹훅 토큰 불일치")
        channel = self.channels[wh.channel_id]
        if self.policy:
            self.policy.on_webhook_execute(self, wh, content, is_image)
        msg = Message(id=self._new_id("msg"), channel_id=channel.id,
                      author_id=f"webhook:{wh.id}", content=content, ts=time.time(),
                      is_image=is_image)
        channel.messages.append(msg)
        return msg

    # ---- 측정 헬퍼 ---------------------------------------------------------
    def count_messages(self, predicate: Callable[[Message], bool] | None = None) -> int:
        total = 0
        for c in self.channels.values():
            for m in c.messages:
                if predicate is None or predicate(m):
                    total += 1
        return total

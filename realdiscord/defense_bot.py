#!/usr/bin/env python3
"""defense_bot.py — 실제 디스코드용 실시간 스캠 방어 봇 (본인 테스트 서버 전용).

이 봇은 **방어 측**입니다. 디스코드 개발자 포털에서 직접 만든 봇 토큰으로,
**본인이 소유한 비공개 테스트 서버**에 추가해 실행하세요. 토큰 탈취/도배 같은
공격 기능은 전혀 없습니다.

기능
----
- 실시간 메시지 스캔: 비트코인 스캠 휴리스틱(scamlab.security.ScamContentScanner)으로
  의심 메시지를 탐지 → 삭제 + 모더레이터 채널에 경보.
- 대량 전파 탐지: 한 작성자가 동일 콘텐츠를 여러 채널에 빠르게 뿌리면 경보(셀프봇 징후).
- !audit (관리자): 서버의 봇/역할 과대 권한과 웹훅을 점검해 보고.

설정 (환경변수)
---------------
- DISCORD_BOT_TOKEN   : 봇 토큰 (필수)
- MOD_CHANNEL_ID      : 경보를 보낼 채널 ID (선택, 없으면 같은 채널에 답)
- SCAMLAB_AUTO_DELETE : "1" 이면 스캠 메시지 자동 삭제 (기본 1)
- SCAMLAB_GUILD_ALLOWLIST : 콤마구분 길드 ID. 지정 시 해당 서버에서만 동작(권장)

설치/실행
---------
    pip install -U "discord.py>=2.3"
    export DISCORD_BOT_TOKEN=...        # 본인 봇 토큰
    export MOD_CHANNEL_ID=123456789
    python realdiscord/defense_bot.py

개발자 포털에서 'MESSAGE CONTENT INTENT' 를 켜야 메시지 본문을 읽을 수 있습니다.
"""

from __future__ import annotations

import os
import sys
import time
from collections import defaultdict, deque

# 샌드박스에서 검증된 탐지 로직을 그대로 재사용
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from scamlab.security import ScamContentScanner  # noqa: E402

try:
    import discord
    from discord.ext import commands
except ImportError:
    print("discord.py 가 필요합니다:  pip install -U 'discord.py>=2.3'")
    raise SystemExit(1)


SCANNER = ScamContentScanner()
BLOCK_THRESHOLD = 2          # 신호 2개 이상이면 스캠으로 간주
FANOUT_CHANNELS = 3          # 같은 글이 3개 채널 이상으로 퍼지면 대량전파
FANOUT_WINDOW_S = 30.0

AUTO_DELETE = os.getenv("SCAMLAB_AUTO_DELETE", "1") == "1"
MOD_CHANNEL_ID = int(os.getenv("MOD_CHANNEL_ID", "0")) or None
_allow = os.getenv("SCAMLAB_GUILD_ALLOWLIST", "").strip()
GUILD_ALLOWLIST = {int(x) for x in _allow.split(",") if x.strip()} if _allow else None

# author_id -> content_hash -> deque[(ts, channel_id)]
_fanout: dict[int, dict[int, deque]] = defaultdict(lambda: defaultdict(deque))

intents = discord.Intents.default()
intents.message_content = True  # 본문 스캔에 필요 (포털에서도 활성화 필요)
bot = commands.Bot(command_prefix="!", intents=intents)


def _fanout_count(author_id: int, channel_id: int, content: str) -> int:
    import re
    now = time.time()
    h = hash(re.sub(r"\s+", " ", content.strip().lower()))
    q = _fanout[author_id][h]
    while q and now - q[0][0] > FANOUT_WINDOW_S:
        q.popleft()
    q.append((now, channel_id))
    return len({cid for _, cid in q})


async def _alert(guild: "discord.Guild", text: str) -> None:
    channel = None
    if MOD_CHANNEL_ID:
        channel = guild.get_channel(MOD_CHANNEL_ID)
    if channel is None:
        channel = guild.system_channel
    if channel is not None:
        try:
            await channel.send(text)
        except discord.DiscordException:
            pass


@bot.event
async def on_ready():
    print(f"[defense_bot] 로그인: {bot.user} (서버 {len(bot.guilds)}개)")
    if GUILD_ALLOWLIST:
        print(f"[defense_bot] 허용 서버로 제한: {GUILD_ALLOWLIST}")


@bot.event
async def on_message(message: "discord.Message"):
    if message.author.bot or message.guild is None:
        return
    if GUILD_ALLOWLIST and message.guild.id not in GUILD_ALLOWLIST:
        return

    score, hits = SCANNER.score(message.content)
    fanout = _fanout_count(message.author.id, message.channel.id, message.content)

    is_scam = score >= BLOCK_THRESHOLD
    is_spam = fanout >= FANOUT_CHANNELS

    if is_scam or is_spam:
        reasons = []
        if is_scam:
            reasons.append(f"스캠콘텐츠(score={score}, {hits})")
        if is_spam:
            reasons.append(f"대량전파({fanout}채널/{FANOUT_WINDOW_S:.0f}s)")
        reason = ", ".join(reasons)

        if AUTO_DELETE:
            try:
                await message.delete()
            except discord.DiscordException:
                pass
        await _alert(
            message.guild,
            f"🚨 **스캠 의심 차단** | 작성자 `{message.author}` | 채널 #{message.channel} | {reason}",
        )
        print(f"[defense_bot] blocked {message.author}: {reason}")
        return

    await bot.process_commands(message)


@bot.command(name="audit")
@commands.has_permissions(administrator=True)
async def audit(ctx: "commands.Context"):
    """서버의 과대 권한 봇/역할과 웹훅을 점검한다 (최소권한 위반 탐지)."""
    g = ctx.guild
    findings: list[str] = []

    # 1) Administrator 권한을 가진 봇
    for m in g.members:
        if m.bot and m.guild_permissions.administrator:
            findings.append(f"- 봇 `{m}` 가 **Administrator** 권한 보유 (과대 권한)")

    # 2) Administrator/위험 권한 역할
    for role in g.roles:
        p = role.permissions
        if p.administrator:
            findings.append(f"- 역할 `{role.name}` 에 **Administrator** 부여")
        elif p.mention_everyone and p.manage_webhooks:
            findings.append(f"- 역할 `{role.name}` 에 @everyone+웹훅관리 동시 부여")

    # 3) 웹훅 점검
    try:
        for ch in g.text_channels:
            for wh in await ch.webhooks():
                findings.append(f"- 웹훅 `{wh.name}` (#{ch.name}) 존재 — URL 유출 주의")
    except discord.Forbidden:
        findings.append("- (웹훅 조회 권한 없음: 봇에 Manage Webhooks 필요)")

    if not findings:
        await ctx.send("✅ 감사 결과: 과대 권한/위험 요소가 발견되지 않았습니다.")
    else:
        head = "🔍 **권한 감사 결과** (최소권한 점검)\n"
        await ctx.send(head + "\n".join(findings[:30]))


if __name__ == "__main__":
    token = os.getenv("DISCORD_BOT_TOKEN")
    if not token:
        print("환경변수 DISCORD_BOT_TOKEN 을 설정하세요 (본인 봇 토큰).")
        raise SystemExit(1)
    bot.run(token)

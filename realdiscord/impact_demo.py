#!/usr/bin/env python3
"""impact_demo.py — '영향' 단계를 본인 서버에서 안전하게 통제 시연.

⚠️ 이 스크립트가 하는 일 / 하지 않는 일
----------------------------------------
하는 일:
- **본인이 만든 봇 토큰**(공식 Bot API)으로,
- **본인이 소유한 단 하나의 비공개 테스트 서버**의 채널들에,
- **명확히 라벨된 테스트용** 스캠 표본 메시지를 보내 → defense_bot 이 잡는지 검증.

하지 않는 일 (의도적으로 구현 안 함):
- 유저 토큰 탈취·셀프봇 로그인 (디스코드 ToS 위반, 계정 정지/타인 피해 위험)
- 다른 서버/타인 대상 발송
- 실제 자금 갈취용 메시지 (표본은 example 도메인의 무해한 더미)

즉, "공격자가 모든 채널에 도배하면 어떻게 보이는지"를 **본인 봇·본인 서버 범위에서**
재현해 방어가 작동하는지 확인하는 용도입니다.

가드 (모두 충족해야 실행됨)
---------------------------
- 환경변수 SCAMLAB_I_OWN_THIS_SERVER=yes      (본인 소유 서버임을 명시적 확인)
- 환경변수 SCAMLAB_TARGET_GUILD_ID=<길드ID>   (대상 서버 1개만)
- 환경변수 DISCORD_BOT_TOKEN=<봇 토큰>

실행:
    pip install -U "discord.py>=2.3"
    export DISCORD_BOT_TOKEN=...
    export SCAMLAB_TARGET_GUILD_ID=123...
    export SCAMLAB_I_OWN_THIS_SERVER=yes
    python realdiscord/impact_demo.py
"""

from __future__ import annotations

import os
import sys

try:
    import discord
except ImportError:
    print("discord.py 가 필요합니다:  pip install -U 'discord.py>=2.3'")
    raise SystemExit(1)

# defense_bot 과 동일한 표본을 쓰되, 테스트임을 분명히 라벨한다.
TEST_LABEL = "[SCAMLAB-TEST·무해한 표본]"
TEST_SCAM_SAMPLE = (
    f"{TEST_LABEL} 🎉 (이것은 방어 테스트용 더미입니다) "
    "double your BTC! send to bc1qexampleexampleexampleexampleexampexx "
    "claim now https://discord-nitro.claim-btc.example"
)
MAX_CHANNELS = 10  # 안전 상한


def _guarded() -> tuple[str, int]:
    token = os.getenv("DISCORD_BOT_TOKEN")
    own = os.getenv("SCAMLAB_I_OWN_THIS_SERVER", "").lower() == "yes"
    gid = os.getenv("SCAMLAB_TARGET_GUILD_ID", "")
    problems = []
    if not token:
        problems.append("DISCORD_BOT_TOKEN 미설정")
    if not own:
        problems.append("SCAMLAB_I_OWN_THIS_SERVER=yes 필요 (본인 소유 서버 확인)")
    if not gid.isdigit():
        problems.append("SCAMLAB_TARGET_GUILD_ID(숫자) 필요")
    if problems:
        print("실행 거부 — 가드 미충족:")
        for p in problems:
            print(f"  - {p}")
        raise SystemExit(2)
    return token, int(gid)


def main() -> int:
    token, target_guild_id = _guarded()

    intents = discord.Intents.default()
    client = discord.Client(intents=intents)

    @client.event
    async def on_ready():
        guild = client.get_guild(target_guild_id)
        if guild is None:
            print(f"대상 길드 {target_guild_id} 를 찾을 수 없습니다(봇이 그 서버에 있나요?).")
            await client.close()
            return
        print(f"[impact_demo] 대상 서버: {guild.name} — 테스트 표본 발송 시작")
        sent = 0
        for ch in guild.text_channels:
            if sent >= MAX_CHANNELS:
                break
            try:
                await ch.send(TEST_SCAM_SAMPLE)
                sent += 1
                print(f"  → #{ch.name} 전송")
            except discord.DiscordException as e:
                print(f"  → #{ch.name} 실패: {e}")
        print(f"[impact_demo] 완료. {sent}개 채널에 전송. "
              f"defense_bot 이 켜져 있으면 즉시 삭제/경보가 보여야 합니다.")
        await client.close()

    client.run(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# realdiscord — 실제 디스코드 확장 (본인 테스트 서버 전용)

샌드박스(`scamlab/`)에서 검증한 로직을 **실제 디스코드**로 가져오는 단계입니다.
단, 여기서는 **합법적이고 안전한 범위**로만 동작합니다.

## ✅ 여기서 하는 것
- `defense_bot.py` — 실시간 **방어 봇**. 본인 비공개 서버의 메시지를 스캔해
  비트코인 스캠/대량전파를 탐지·삭제·경보하고, `!audit` 로 과대 권한 봇/역할/웹훅을 점검.
- `impact_demo.py` — **본인 소유 서버 1곳**에서 공식 Bot API로 *라벨된 무해한 표본*을
  여러 채널에 보내, 방어 봇이 실제로 잡는지 검증하는 **통제된 시연**.

## ❌ 여기서 하지 않는 것 (그리고 그 이유)
- **유저 토큰 탈취 / 셀프봇 로그인 / 도배** — 만들지 않습니다.
  - 토큰 그래버·셀프봇은 "본인 계정"이라도 그대로 **타인 계정에 동작하는 무기**이고,
    실행 시 **디스코드 ToS 위반 → 계정·서버 정지**, 그리고 같은 서버의 **실제 사용자에게
    피해**가 갑니다. 그래서 이 부분은 `scamlab/` 샌드박스(메모리, 외부 무접속) 안에만 둡니다.
  - "공격이 어떻게 동작하는가"는 샌드박스에서 충분히, 정확히 재현됩니다.
- 본인 소유가 아닌 서버/타인 대상 그 어떤 행위도 하지 않습니다.

> 요약: **공격 메커니즘 이해 = 샌드박스에서**, **실제 디스코드 = 방어/통제 시연만.**

## 사전 준비
1. https://discord.com/developers/applications 에서 **Application → Bot** 생성, 토큰 복사.
2. Bot 설정에서 **MESSAGE CONTENT INTENT** 활성화.
3. **본인만 있는 비공개 테스트 서버**를 새로 만들고, OAuth2 URL로 봇 초대
   (권한은 최소로: Read Messages, Send Messages, Manage Messages, Manage Webhooks 정도).
4. `pip install -U "discord.py>=2.3"`

## 실행: 방어 봇
```bash
export DISCORD_BOT_TOKEN=<봇 토큰>
export MOD_CHANNEL_ID=<경보 받을 채널 ID>          # 선택
export SCAMLAB_GUILD_ALLOWLIST=<테스트 서버 ID>    # 권장: 그 서버에서만 동작
python realdiscord/defense_bot.py
```

## 실행: 통제된 영향 시연 (방어 봇을 켠 채로, 다른 터미널에서)
```bash
export DISCORD_BOT_TOKEN=<같은 봇 토큰>
export SCAMLAB_TARGET_GUILD_ID=<테스트 서버 ID>
export SCAMLAB_I_OWN_THIS_SERVER=yes
python realdiscord/impact_demo.py
```
표본 메시지가 채널들에 올라가는 즉시 `defense_bot` 이 삭제하고 모더레이터 채널에
경보를 남기는지 확인하세요. 이것이 "탈취 시 도배되는 모습"과 "방어가 막는 모습"을
본인 환경에서 안전하게 검증하는 방법입니다.

## 주의
- `impact_demo.py` 의 표본은 `example` 도메인의 **무해한 더미**이며 실제 지갑이 아닙니다.
- 시연 후에는 채널을 정리하고, 테스트가 끝나면 봇 토큰을 폐기(reset)하는 것을 권장합니다.

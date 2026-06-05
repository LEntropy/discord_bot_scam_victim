# 아키텍처 & 설계

## 목표
1. 디스코드 계정 탈취 스캠 체인을 **안전한 샌드박스**에서 정확히 재현한다.
2. 각 단계를 끊는 **방어 계층**을 구현하고, 켜고/끄며 효과를 정량 비교한다.
3. 이후 **본인 비공개 테스트 서버**에서만 동작하는 **실제 디스코드 방어 봇**으로 확장한다.

## 안전 원칙 (Safety by Design)
- 샌드박스(`scamlab/`)는 **실제 디스코드를 호출하지 않는다.** 모든 상태는 메모리.
- 실제 토큰 추출/DPAPI 복호화/웹훅 유출 같은 **무기화 기능은 구현하지 않는다.**
  공격 모듈은 "개념의 흐름"만 재현한다.
- 실제 디스코드 대상 코드(`realdiscord/`)는 **방어 봇**과, 본인 소유 서버에서만
  동작하도록 가드된 **통제된 영향 시연**뿐이다. 토큰 탈취/셀프봇 도배는 포함하지 않는다.

## 구성 요소

```
discord_bot_scam_victim/
├── scamlab/                  # 핵심 라이브러리 (외부 의존성 0)
│   ├── platform.py           # MockDiscord: 유저/토큰/길드/채널/OAuth/봇/웹훅 + 보안 훅
│   ├── security.py           # SecurityPolicy + 탐지기들(방어)
│   ├── attacks.py            # 공격 체인 시뮬레이션(샌드박스 전용)
│   └── scenarios.py          # 취약 vs 방어 비교 시나리오
├── demo.py                   # CLI 시연
├── app.py                    # (선택) FastAPI 라이브 데모
├── realdiscord/              # 실제 디스코드 확장 (본인 테스트 서버 전용)
│   ├── defense_bot.py        # discord.py 기반 실시간 방어 봇
│   ├── impact_demo.py        # 통제된 영향 시연(가드 필수)
│   └── README.md             # 설정/실행 가이드 + 안전 경계
├── tests/                    # pytest
└── docs/                     # 본 문서들
```

### MockDiscord (platform.py)
디스코드의 핵심 인증 모델만 최소 재현:
- **유저 토큰**: 계정 인증의 전부. 토큰 인덱스로 행위자 식별.
- **인증 관문 `authenticate()`**: 모든 민감 동작이 거쳐가는 단일 지점. 여기서
  보안 정책 훅이 호출된다(토큰 바인딩 등).
- **데스크톱 금고 `LocalStorageVault`**: LevelDB+DPAPI를 단순화한 토큰 저장소.

### SecurityPolicy (security.py)
탐지기 6종(토큰 바인딩 / 레이트리밋 / 대량전파 / 콘텐츠 스캐너 / 스코프 최소화 /
봇 권한 감사)을 조립. 개별 on/off로 "어떤 방어가 어떤 공격을 막는가"를 실험.

### 보안 훅 흐름
```
attacker → MockDiscord.send_message(token, channel, scam)
                 │
                 ├─ authenticate(token, fingerprint)  → policy.on_authenticate   (토큰 바인딩)
                 └─ policy.on_send_message(...)        → 콘텐츠 스캔 / 레이트리밋 / 대량전파
                          │
                          └─ SecurityBlocked 예외 → 메시지 차단 + 감사 로그 ALERT
```

## 데이터 흐름 (시나리오)
1. `build_world()` — 피해자 1, 서버 4, 채널 20 생성. 데스크톱 로그인으로 금고에 토큰 저장.
2. 진입: `token_grabber_sim` / `qr_login_sim` / `oauth_phish_sim` 중 하나.
3. 영향: `mass_spam` 이 모든 채널을 열거해 스캠 전송 시도.
4. 측정: 채널에 실제 도달한 스캠 수, 차단 수, 경보 수를 집계해 비교.

## 확장 포인트
- 새 공격: `attacks.py` 에 함수 추가 후 `scenarios.run_chain` 의 `entry` 분기 연결.
- 새 방어: `security.py` 에 탐지기 추가 후 `SecurityPolicy` 훅에서 호출.
- 실제 디스코드: `realdiscord/defense_bot.py` 가 동일한 탐지기를 재사용.

# discord_bot_scam_victim — 디스코드 계정 탈취 스캠 재현 & 방어 랩

요즘 유행하는 **"이상한 링크/봇 권한 → 계정 토큰 탈취 → 가입한 모든 서버·채널에
비트코인 스캠 도배"** 위협을, **안전한 샌드박스**에서 정확히 재현하고 **방어**까지
한 프로젝트로 구현한 교육용 보안 랩입니다.

> ⚠️ **안전 원칙**: 핵심 샌드박스(`scamlab/`)는 **실제 디스코드를 호출하지 않습니다.**
> 실제 토큰 추출/유출·셀프봇 도배 같은 무기화 기능은 **구현하지 않았습니다.**
> 실제 디스코드 대상 코드(`realdiscord/`)는 **방어 봇**과 **본인 서버 한정 통제 시연**뿐입니다.

## 이게 무슨 취약점인가? (요약)
단일 CVE가 아니라 **계정 탈취(ATO) 스캠 체인**입니다. 핵심은 디스코드 **유저 토큰** —
토큰만 있으면 비밀번호·2FA 없이 계정 전체를 쓸 수 있습니다. 공격자는
(A) 토큰 그래버 멀웨어, (B) 가짜 verify OAuth 피싱, (C) QR 로그인 스캠, (D) 과대 권한 봇
중 하나로 토큰/세션을 탈취한 뒤, **셀프봇**으로 모든 길드의 모든 채널에 스캠을 살포합니다.
정확한 분석과 출처는 **[docs/VULNERABILITY.md](docs/VULNERABILITY.md)**.

## 빠른 시작
```bash
python3 demo.py                      # 취약 vs 방어 비교 (의존성 0)
python3 demo.py --entry qr_login     # 다른 진입 경로
make install && make test            # 테스트(pytest)
make app                             # (선택) FastAPI 라이브 데모
```

`demo.py` 출력 예: 방어 없음 → 스캠 **20개 채널 전부 도배** / 방어 적용 → **0건 도달 + 경보**.

## 구조
```
scamlab/      핵심 라이브러리(외부 의존성 0)
  platform.py   MockDiscord: 유저/토큰/길드/채널/OAuth/봇/웹훅 + 보안 훅
  security.py   SecurityPolicy + 탐지기 6종(방어)
  attacks.py    공격 체인 시뮬레이션(샌드박스 전용)
  scenarios.py  취약 vs 방어 비교
demo.py        CLI 시연
app.py         (선택) FastAPI 라이브 데모
realdiscord/   실제 디스코드 확장(본인 테스트 서버 전용): 방어 봇 + 통제 시연
tests/         pytest
docs/          VULNERABILITY / ARCHITECTURE / ROADMAP
```
설계 상세 → [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · 진행/계획 → [docs/ROADMAP.md](docs/ROADMAP.md)

## 공격 ↔ 방어 매핑
| 공격 단계 | 방어 |
|---|---|
| 토큰 그래버 / QR 탈취 (낯선 기기) | 토큰-기기 바인딩 + 재인증 |
| 셀프봇 대량 살포 | 레이트리밋 · 대량전파 이상탐지 |
| 비트코인 스캠 콘텐츠 | 콘텐츠 스캐너(주소/미끼문구/링크) |
| OAuth 피싱(과대 스코프) | 스코프 최소화 |
| 과대 권한 봇 / 웹훅 | 봇 권한 감사 · 웹훅 검사 |

## 실제 디스코드에서 직접 재현하고 싶다면
본인 **비공개 테스트 서버**에서 **방어 봇**을 돌리고, **통제된 영향 시연**으로
"도배되는 모습"과 "방어가 막는 모습"을 확인하세요. 토큰 탈취/셀프봇은 ToS 위반·타인
피해 때문에 다루지 않습니다. 자세한 경계와 실행법 → **[realdiscord/README.md](realdiscord/README.md)**.

## 면책
이 저장소는 **방어 연구·교육 목적**입니다. 모든 실습은 본인이 소유·통제하는 환경에서만
수행하세요.

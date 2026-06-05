#!/usr/bin/env python3
"""demo.py — 디스코드 계정 탈취 스캠 체인을 안전한 샌드박스에서 시연.

사용법:
    python demo.py                 # token_grabber 진입으로 방어 전/후 비교
    python demo.py --entry qr_login
    python demo.py --entry oauth_phish

실제 디스코드를 건드리지 않습니다. 전부 메모리상의 MockDiscord 에서 동작합니다.
"""

import argparse

from scamlab.scenarios import compare


def _bar(title: str) -> None:
    print("\n" + "=" * 64)
    print(f"  {title}")
    print("=" * 64)


def _print(result) -> None:
    print(f"\n[{result.label}]")
    for n in result.notes:
        print(f"  - {n}")
    print(f"  ▶ 진입(계정 탈취) 성공: {result.grabber_ok}")
    print(f"  ▶ 채널에 도달한 스캠 메시지: {result.spam_delivered} 건")
    print(f"  ▶ 차단된 스캠 시도: {result.spam_blocked} 건")
    print(f"  ▶ 보안 경보(alert): {result.alerts} 건")


def main() -> int:
    ap = argparse.ArgumentParser(description="Discord scam chain sandbox demo")
    ap.add_argument("--entry", default="token_grabber",
                    choices=["token_grabber", "qr_login", "oauth_phish"],
                    help="초기 침투 방식")
    args = ap.parse_args()

    _bar(f"디스코드 계정 탈취 → 비트코인 스캠 살포 시연 (진입: {args.entry})")
    insecure, secure = compare(entry=args.entry)
    _print(insecure)
    _print(secure)

    _bar("결론")
    print(f"  방어 없음: 스캠 {insecure.spam_delivered}건이 모든 채널에 도배됨.")
    print(f"  방어 적용: 스캠 {secure.spam_delivered}건만 도달 (차단 {secure.spam_blocked}건, "
          f"경보 {secure.alerts}건).")
    if secure.spam_delivered == 0:
        print("  ✅ 방어 계층이 스캠 체인을 완전히 차단했습니다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

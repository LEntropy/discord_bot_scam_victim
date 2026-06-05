"""scamlab — 디스코드 계정 탈취 스캠을 안전하게 재현하고 방어하는 교육용 샌드박스.

이 패키지는 실제 디스코드(discord.com)를 대상으로 하지 않습니다.
모든 공격/방어는 메모리 상의 모의 플랫폼(MockDiscord)에서만 동작합니다.
"""

from .platform import (
    MockDiscord,
    SecurityBlocked,
    User,
    Guild,
    Channel,
    Message,
)
from .security import SecurityPolicy

__all__ = [
    "MockDiscord",
    "SecurityPolicy",
    "SecurityBlocked",
    "User",
    "Guild",
    "Channel",
    "Message",
]

__version__ = "0.1.0"

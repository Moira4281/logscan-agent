"""配置管理：从环境变量 / .env 读取。"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


@dataclass
class Settings:
    api_key: str = ""
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    max_steps: int = 20
    max_log_lines: int = 50000
    db_path: str = ":memory:"
    disable_thinking: bool = False
    extra_stop_patterns: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, env_path: Path | None = None) -> "Settings":
        if env_path and env_path.exists():
            load_dotenv(env_path)
        else:
            load_dotenv()
        return cls(
            api_key=os.getenv("OPENAI_API_KEY", ""),
            base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            model=os.getenv("LOGSCAN_MODEL", "gpt-4o-mini"),
            max_steps=int(os.getenv("LOGSCAN_MAX_STEPS", "20")),
            max_log_lines=int(os.getenv("LOGSCAN_MAX_LOG_LINES", "50000")),
            db_path=os.getenv("LOGSCAN_DB_PATH", ":memory:"),
            disable_thinking=os.getenv("LOGSCAN_DISABLE_THINKING", "0").strip() in ("1", "true", "True"),
        )
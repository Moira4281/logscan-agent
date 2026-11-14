"""ChatAgent 单元测试：用假 LLM 客户端验证工具调用循环与最终回答。"""

from __future__ import annotations

from types import SimpleNamespace

from logscan.chat import ChatAgent
from logscan.config import Settings
from logscan.logs.store import LogStore
from logscan.logs.parser import parse_line


def _make_store() -> LogStore:
    s = LogStore(":memory:")
    line = '10.0.0.66 - - [15/Jan/2024:10:01:02 +0000] "GET /products?id=1 HTTP/1.1" 200 120 "-" "curl"'
    s.insert(parse_line(line), "test.log", 1)
    s.conn.commit()
    return s


def _settings() -> Settings:
    return Settings(api_key="fake", base_url="http://x/v1", model="fake", max_steps=5)


class _FakeMessage:
    def __init__(self, content: str = "", tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []

    def model_dump(self, exclude_none: bool = False) -> dict:
        d = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            d["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in self.tool_calls
            ]
        return d


class _FakeChoice:
    def __init__(self, message: _FakeMessage):
        self.message = message


class _FakeResp:
    def __init__(self, choice):
        self.choices = [choice]


class _FakeToolCall:
    def __init__(self, name: str, args: str, call_id: str = "tc1"):
        self.id = call_id
        self.function = SimpleNamespace(name=name, arguments=args)


class _FakeClient:
    """按预设序列依次返回响应，模拟 LLM 多次往返。"""

    def __init__(self, responses):
        self._responses = list(responses)
        self.chat = self
        self.completions = self

    def create(self, **kwargs):
        assert self._responses, "FakeClient 没有更多响应了"
        return self._responses.pop(0)


def test_chat_no_tool_call_returns_answer():
    store = _make_store()
    client = _FakeClient([_FakeResp(_FakeChoice(_FakeMessage(content="日志正常，未发现攻击。")))])
    agent = ChatAgent(_settings(), store, client=client)
    result = agent.chat("这批日志有问题吗？")
    assert result.success
    assert result.answer == "日志正常，未发现攻击。"
    assert len(result.trace.steps) >= 1


def test_chat_tool_call_then_final():
    store = _make_store()
    # 第一轮：调用 get_stats；第二轮：给最终回答
    client = _FakeClient([
        _FakeResp(_FakeChoice(_FakeMessage(
            content=None,
            tool_calls=[_FakeToolCall("get_stats", "{}")],
        ))),
        _FakeResp(_FakeChoice(_FakeMessage(content="共 1 条日志，状态正常。"))),
    ])
    agent = ChatAgent(_settings(), store, client=client)
    result = agent.chat("日志概况？")
    assert result.success
    assert result.answer == "共 1 条日志，状态正常。"
    types = [s.type for s in result.trace.steps]
    assert "tool_call" in types
    assert "tool_result" in types
    assert "final" in types


def test_chat_maintains_history_across_turns():
    store = _make_store()
    client = _FakeClient([
        _FakeResp(_FakeChoice(_FakeMessage(content="第一轮回答"))),
        _FakeResp(_FakeChoice(_FakeMessage(content="第二轮回答"))),
    ])
    agent = ChatAgent(_settings(), store, client=client)
    agent.chat("第一个问题")
    # 第二轮历史里应包含第一轮的 user + assistant
    assert len(agent.messages) == 3  # system + user1 + assistant1
    result = agent.chat("第二个问题")
    assert result.answer == "第二轮回答"
    assert len(agent.messages) == 5


def test_chat_reset_clears_history():
    store = _make_store()
    client = _FakeClient([_FakeResp(_FakeChoice(_FakeMessage(content="ok")))])
    agent = ChatAgent(_settings(), store, client=client)
    agent.chat("q")
    agent.reset()
    assert len(agent.messages) == 1  # 只剩 system


def test_chat_llm_error_returns_failure():
    store = _make_store()

    class _BoomClient:
        def __init__(self):
            self.chat = self
            self.completions = self

        def create(self, **kwargs):
            raise RuntimeError("boom")

    agent = ChatAgent(_settings(), store, client=_BoomClient())
    result = agent.chat("q")
    assert not result.success
    assert "boom" in result.error

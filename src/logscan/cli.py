"""CLI 入口。"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import Settings
from .logs.store import LogStore
from .agent import LogScanAgent
from .report.renderer import render_json, render_markdown, render_trace_table

console = Console()


@click.group()
def cli() -> None:
    """logscan: LLM 驱动的安全日志漏洞扫描智能体。"""


@cli.command()
@click.argument("sources", nargs=-1, required=True)
@click.option("--model", default=None, help="覆盖模型名称")
@click.option("--max-steps", default=None, type=int, help="Agent 最大推理步数")
@click.option("--max-lines", default=None, type=int, help="每个日志文件最大读取行数")
@click.option("--format", "fmt", default="markdown",
              type=click.Choice(["markdown", "json"]), help="输出格式")
@click.option("--output", "-o", default=None, type=click.Path(), help="输出到文件")
@click.option("--verbose", is_flag=True, help="显示详细分析过程")
@click.option("--mock", is_flag=True, help="使用 mock 模式（不调用 LLM，用规则模拟分析）")
@click.option("--env-file", default=".env", type=click.Path(), help=".env 文件路径")
def scan(sources, model, max_steps, max_lines, fmt, output, verbose, mock, env_file):
    """扫描安全日志，分析漏洞。

    SOURCES: 日志文件或目录路径（支持多个），"-" 表示 stdin
    """
    env_path = Path(env_file) if env_file else None
    settings = Settings.load(env_path)
    if model:
        settings.model = model
    if max_steps:
        settings.max_steps = max_steps
    if max_lines:
        settings.max_log_lines = max_lines

    if not mock and not settings.api_key:
        console.print("[red]错误: 未配置 OPENAI_API_KEY[/red]")
        console.print("请复制 .env.example 为 .env 并填入 API Key，或设置环境变量。")
        console.print("[dim]提示: 也可使用 --mock 模式无需 API Key 运行[/dim]")
        sys.exit(1)

    src_list = list(sources)

    # 加载日志
    console.print(f"[cyan]加载日志源:[/cyan] {', '.join(src_list)}")
    store = LogStore(settings.db_path)
    try:
        count = store.ingest_sources(src_list, settings.max_log_lines)
    except FileNotFoundError as exc:
        console.print(f"[red]错误: {exc}[/red]")
        sys.exit(1)

    if count == 0:
        console.print("[yellow]警告: 未加载到任何日志条目[/yellow]")
        sys.exit(0)

    console.print(f"[green]已加载 {count} 条日志[/green]")

    # 显示日志概览
    ts_min, ts_max = store.time_range()
    console.print(f"  时间范围: {ts_min} ~ {ts_max}")
    console.print(f"  级别分布: {', '.join(f'{r[0]}={r[1]}' for r in store.stats_by_level())}")
    console.print("")

    # 运行 Agent
    if mock:
        console.print("[cyan]启动分析智能体 (mock 模式)...[/cyan]")
        from .mock_agent import MockAgent
        agent = MockAgent(store)
    else:
        console.print("[cyan]启动分析智能体...[/cyan]")
        agent = LogScanAgent(settings, store)

    if verbose:
        with console.status("[dim]分析中...[/dim]"):
            result = agent.run(src_list)
    else:
        result = agent.run(src_list)

    # 显示分析过程
    if verbose:
        table = Table(title="分析过程", show_lines=False)
        table.add_column("Step", style="dim", width=5)
        table.add_column("Type", style="cyan", width=14)
        table.add_column("Detail", style="white")
        for row in render_trace_table(result.trace):
            table.add_row(*row)
        console.print(table)

    console.print(f"[dim]分析耗时: {result.trace.total_elapsed_ms}ms, "
                  f"步数: {len(result.trace.steps)}[/dim]")

    # 渲染报告
    if not result.success:
        console.print(f"[yellow]警告: {result.error}[/yellow]")

    if fmt == "json":
        output_text = render_json(result.report)
    else:
        output_text = render_markdown(result.report, result.trace)

    if output:
        Path(output).write_text(output_text, encoding="utf-8")
        console.print(f"[green]报告已写入: {output}[/green]")
    else:
        if fmt == "markdown":
            console.print(Panel(output_text, title="分析报告", border_style="green"))
        else:
            console.print(output_text)

    vulns = result.report.get("vulnerabilities", [])
    console.print(f"\n[bold]发现漏洞: {len(vulns)} 个[/bold]")

    store.close()


@cli.command()
@click.argument("sources", nargs=-1, required=True)
@click.option("--max-lines", default=100, type=int)
def preview(sources, max_lines):
    """预览日志解析结果（不调用 LLM）。"""
    from .logs.loader import load_sources
    from .logs.parser import parse_line

    table = Table(title="日志解析预览")
    table.add_column("#", style="dim", width=4)
    table.add_column("Timestamp", width=26)
    table.add_column("Level", width=9)
    table.add_column("IP", width=15)
    table.add_column("Message", style="white")

    for i, (src, line) in enumerate(load_sources(list(sources), max_lines), 1):
        if not line.strip():
            continue
        e = parse_line(line)
        level_style = {"ERROR": "red", "WARN": "yellow", "CRITICAL": "red bold"}.get(e.level, "green")
        table.add_row(
            str(i), e.timestamp, f"[{level_style}]{e.level}[/{level_style}]",
            e.source_ip, e.message[:60],
        )
        if i >= max_lines:
            break

    console.print(table)


def main():
    cli()


@cli.command()
@click.argument("sources", nargs=-1, required=True)
@click.option("--mode", default="llm", type=click.Choice(["mock", "llm"]),
              help="mock=规则模拟不调 LLM；llm=调用 LLM 智能体")
@click.option("--ask", default=None, help="单次提问（不进交互模式）")
@click.option("--max-lines", default=None, type=int, help="每个日志文件最大读取行数")
@click.option("--max-steps", default=None, type=int, help="Agent 最大推理步数")
@click.option("--env-file", default=".env", type=click.Path(), help=".env 文件路径")
def chat(sources, mode, ask, max_lines, max_steps, env_file):
    """自然语言问答：加载日志后用自然语言提问，智能体调用工具回答。

    SOURCES: 日志文件或目录路径（支持多个）
    """
    env_path = Path(env_file) if env_file else None
    settings = Settings.load(env_path)
    if max_steps:
        settings.max_steps = max_steps
    if max_lines:
        settings.max_log_lines = max_lines

    src_list = list(sources)
    store = LogStore(settings.db_path)
    try:
        count = store.ingest_sources(src_list, settings.max_log_lines)
    except FileNotFoundError as exc:
        console.print(f"[red]错误: {exc}[/red]")
        sys.exit(1)

    if count == 0:
        console.print("[yellow]警告: 未加载到任何日志条目[/yellow]")
        sys.exit(0)

    console.print(f"[cyan]已加载 {count} 条日志 (mode={mode})[/cyan]")

    if mode == "llm":
        if not settings.api_key:
            console.print("[red]错误: 未配置 OPENAI_API_KEY，请用 --mode mock 或配置 .env[/red]")
            sys.exit(1)
        from .chat import ChatAgent
        agent = ChatAgent(settings, store)

        def _answer(q: str) -> str:
            with console.status("[dim]思考中...[/dim]"):
                result = agent.chat(q)
            if not result.success:
                return f"[yellow]{result.error}[/yellow]"
            return result.answer
    else:
        from .agentarts.service import _mock_chat_answer

        def _answer(q: str) -> str:
            return _mock_chat_answer(store, q)

    if ask:
        console.print(_answer(ask))
        return

    # 交互模式
    console.print("[dim]输入问题后回车提问，输入 quit / exit / Ctrl-D 退出[/dim]")
    while True:
        try:
            question = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]再见[/dim]")
            break
        if question in ("quit", "exit", "q"):
            break
        if not question:
            continue
        console.print(_answer(question))

    store.close()


if __name__ == "__main__":
    main()
"""Generic subprocess runner for the Go recon/detection binaries baked into
the image (subfinder, dnsx, httpx, nuclei) plus nmap. Mirrors BB_Assist's
tool_runner.py pattern, scoped down to non-destructive tools only."""

import asyncio
import json
import shutil


class ToolNotAvailable(Exception):
    pass


async def run(cmd: list[str], timeout: int = 120, input_data: str | None = None) -> tuple[str, str, int]:
    if shutil.which(cmd[0]) is None:
        raise ToolNotAvailable(cmd[0])

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if input_data is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdin_bytes = input_data.encode() if input_data is not None else None
        stdout, stderr = await asyncio.wait_for(proc.communicate(stdin_bytes), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise

    return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode


def parse_jsonlines(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def is_available(binary: str) -> bool:
    return shutil.which(binary) is not None

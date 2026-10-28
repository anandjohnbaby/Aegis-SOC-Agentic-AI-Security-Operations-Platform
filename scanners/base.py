"""Base scanner: runs a real binary when available, else returns mock findings."""
from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod

from shared.config import get_settings
from shared.schemas import Finding, ScanResult
from observability.logging import get_logger

logger = get_logger(__name__)


class BaseScanner(ABC):
    name: str = "base"
    binary: str = ""

    def available(self) -> bool:
        return bool(self.binary) and shutil.which(self.binary) is not None

    def scan(self, target: str) -> ScanResult:
        s = get_settings()
        if s.mock_mode:
            logger.info("scanner.mock", extra={"scanner": self.name})
            return ScanResult(scanner=self.name, target=target,
                              findings=self.mock_findings(target), mock=True)
        # LIVE mode: never return fake findings.
        if self.available():
            try:
                raw = self._run(target)
                return ScanResult(scanner=self.name, target=target,
                                  findings=self.parse(raw, target))
            except Exception as exc:
                logger.warning("scanner.error", extra={"scanner": self.name,
                                                        "err": str(exc)})
                return ScanResult(scanner=self.name, target=target, error=str(exc))
        # tool not installed -> built-in pure-Python scanner (if this one has it)
        try:
            findings = self.native_scan(target)
        except Exception as exc:
            logger.warning("scanner.native_error", extra={"scanner": self.name,
                                                           "err": str(exc)})
            return ScanResult(scanner=self.name, target=target, error=str(exc))
        if findings is None:
            return ScanResult(scanner=self.name, target=target,
                              error=f"{self.binary} not installed and no built-in scanner")
        return ScanResult(scanner=self.name, target=target, findings=findings)

    def native_scan(self, target: str):
        """Override to provide a built-in scanner. Return None if unsupported."""
        return None

    def _run(self, target: str) -> str:
        cmd = self.command(target)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return proc.stdout

    @abstractmethod
    def command(self, target: str) -> list[str]: ...

    @abstractmethod
    def parse(self, raw: str, target: str) -> list[Finding]: ...

    @abstractmethod
    def mock_findings(self, target: str) -> list[Finding]: ...

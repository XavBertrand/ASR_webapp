import runpy
import sys
import types
from pathlib import Path


class DummyRule:
    def __init__(self, rule: str):
        self.rule = rule

    def __str__(self) -> str:
        return self.rule


class DummyUrlMap:
    def __init__(self, rules):
        self._rules = rules

    def iter_rules(self):
        return self._rules


class DummyApp:
    def __init__(self):
        self.run_calls = []
        self.url_map = DummyUrlMap([DummyRule("/"), DummyRule("/health")])

    def run(self, host=None, port=None, debug=None):
        self.run_calls.append({"host": host, "port": port, "debug": debug})


def test_debug_app_runs_with_stub(monkeypatch, capsys):
    dummy_app = DummyApp()
    stub_module = types.ModuleType("app")
    stub_module.app = dummy_app
    monkeypatch.setitem(sys.modules, "app", stub_module)

    debug_path = Path(__file__).resolve().parents[1] / "server" / "debug_app.py"
    runpy.run_path(str(debug_path))

    output = capsys.readouterr().out
    assert "Import OK" in output
    assert "Routes:" in output
    assert dummy_app.run_calls == [{"host": "0.0.0.0", "port": 8000, "debug": True}]

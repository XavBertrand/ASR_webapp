from datetime import datetime, timezone

import pytest

from server.app import DEFAULT_MEETING_REPORT_LABELS, extract_metadata


def test_extract_metadata_defaults(monkeypatch):
    monkeypatch.delenv("ASR_CONFIG_DIR", raising=False)
    data = extract_metadata({})
    assert data["meeting_date"] == datetime.now(timezone.utc).date().isoformat()
    assert data["meeting_report_type"] in DEFAULT_MEETING_REPORT_LABELS
    assert data["case_name"] == ""
    assert data["speaker_context"] == ""
    assert data["asr_prompt"]


def test_extract_metadata_valid_values(monkeypatch):
    monkeypatch.delenv("ASR_CONFIG_DIR", raising=False)
    data = extract_metadata(
        {
            "meeting_date": "2024-01-02",
            "meeting_report_type": "entretien_collaborateur",
            "case_name": "Case 42",
            "speaker_context": "Speaker A",
            "asr_prompt": "Prompt",
        }
    )
    assert data["meeting_date"] == "2024-01-02"
    assert data["meeting_report_type"] == "entretien_collaborateur"
    assert data["case_name"] == "Case 42"
    assert data["speaker_context"] == "Speaker A"
    assert data["asr_prompt"] == "Prompt"


def test_extract_metadata_validation(monkeypatch):
    monkeypatch.delenv("ASR_CONFIG_DIR", raising=False)
    with pytest.raises(ValueError):
        extract_metadata({"meeting_date": "not-a-date"})
    with pytest.raises(ValueError):
        extract_metadata({"meeting_report_type": "invalid"})
    with pytest.raises(ValueError):
        extract_metadata({"case_name": "a" * 161})

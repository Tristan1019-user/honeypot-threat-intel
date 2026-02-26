import asyncio
import json
from pathlib import Path

from app.pipeline import process_cowrie_log


def test_pipeline_updates_last_run_even_when_no_new_events(tmp_path: Path):
    log_path = tmp_path / 'cowrie.json'
    state_path = tmp_path / 'pipeline_state.json'
    db_path = tmp_path / 'ti.db'

    log_path.write_text('')
    state_path.write_text(json.dumps({
        'last_file': str(log_path),
        'last_line_offset': 0,
        'last_run': '2026-01-01T00:00:00+00:00',
        'sessions_processed': 0,
    }))

    res = asyncio.run(process_cowrie_log(str(log_path), state_path=str(state_path), db_path=str(db_path)))
    assert res['new_events'] == 0

    state = json.loads(state_path.read_text())
    assert state.get('last_run')
    assert state['last_run'] != '2026-01-01T00:00:00+00:00'

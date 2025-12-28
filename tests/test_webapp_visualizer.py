from pathlib import Path


def test_recording_visualizer_hook_present():
    html = Path("webapp/index.html").read_text(encoding="utf-8")
    assert 'id="visualizerContainer"' in html
    assert 'id="audioCanvas"' in html

    start_idx = html.find("async startRecording()")
    assert start_idx != -1
    resize_idx = html.find("this.resizeCanvas()", start_idx)
    draw_idx = html.find("this.drawVisualizer()", start_idx)
    assert resize_idx != -1
    assert draw_idx != -1
    assert resize_idx < draw_idx

    guard = "if (this.canvas.width === 0 || this.canvas.height === 0)"
    assert guard in html
    assert "this.resizeCanvas()" in html[html.find(guard) :]

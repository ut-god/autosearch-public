"""Tests for overlay section parsing and per-target trimming."""
from autosearch.store.workspace import _parse_sections, _trim_attacker_surface


def _make_large_overlay(*section_names: str) -> str:
    """Build an overlay with enough lines to trigger trimming."""
    lines = ["Trust classes:", "  trust_a — RAW ATTACKER BYTES", "  trust_b — INTS", ""]
    for name in section_names:
        lines.append(f"=== {name} ===")
        for i in range(10):
            lines.append(f"  entry_{i}: trust_b")
        lines.append("")
    return "\n".join(lines)


SAMPLE = _make_large_overlay(
    "GPUDevice (GPUDevice.idl) — central factory",
    "GPUBuffer (GPUBuffer.idl) — HOT MEMORY-CORRUPTION SURFACE",
    "GPUQueue (GPUQueue.idl) — HIGHEST-VALUE TRUST_A SURFACE",
    "GPUTexture / GPUTextureView",
    "GPURenderPassEncoder (GPURenderPassEncoder.idl)",
    "Cross-cutting attacker primitives",
)


class TestParseSections:
    def test_basic_parsing(self):
        sections = _parse_sections(SAMPLE)
        names = [n for n, _ in sections]
        assert "preamble" in names
        assert any("GPUBuffer" in n for n in names)
        assert any("Cross-cutting" in n for n in names)

    def test_preamble_first(self):
        sections = _parse_sections(SAMPLE)
        assert sections[0][0] == "preamble"
        assert "trust_a" in sections[0][1]

    def test_no_markers_returns_single(self):
        sections = _parse_sections("plain text no markers")
        assert len(sections) == 1
        assert sections[0][0] == "preamble"

    def test_empty_string(self):
        assert _parse_sections("") == []


class TestTrimAttackerSurface:
    def test_class_match(self):
        trimmed = _trim_attacker_surface(SAMPLE, "WebGPU::Buffer", "")
        assert "GPUBuffer" in trimmed
        assert "GPURenderPassEncoder" not in trimmed
        assert "GPUQueue" not in trimmed

    def test_always_includes_preamble(self):
        trimmed = _trim_attacker_surface(SAMPLE, "WebGPU::Buffer", "")
        assert "trust_a" in trimmed

    def test_always_includes_cross_cutting(self):
        trimmed = _trim_attacker_surface(SAMPLE, "WebGPU::Buffer", "")
        assert "Cross-cutting" in trimmed

    def test_source_path_match(self):
        trimmed = _trim_attacker_surface(SAMPLE, "", "Source/WebGPU/WebGPU/Queue.mm")
        assert "GPUQueue" in trimmed
        assert "GPUBuffer" not in trimmed

    def test_no_match_returns_always_include_sections(self):
        trimmed = _trim_attacker_surface(SAMPLE, "SomeUnrelatedClass", "")
        # Always-include sections (preamble + cross-cutting) still present
        assert "trust_a" in trimmed
        assert "Cross-cutting" in trimmed
        # Target-specific sections excluded
        assert "GPUBuffer" not in trimmed
        assert "GPUQueue" not in trimmed

    def test_small_overlay_skips_trimming(self):
        small = "=== GPUBuffer ===\nentry1\n=== GPUQueue ===\nentry2"
        trimmed = _trim_attacker_surface(small, "WebGPU::Buffer", "")
        assert trimmed == small  # too short, returned unchanged

    def test_trim_reduces_size(self):
        trimmed = _trim_attacker_surface(SAMPLE, "WebGPU::Buffer", "")
        assert len(trimmed) < len(SAMPLE)

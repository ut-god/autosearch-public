from autosearch.store.workspace import parse_targets
from autosearch.targets import split_qualified_target


def test_split_qualified_target_ignores_namespaces_in_parameter_types():
    split = split_qualified_target(
        "WebCore::ImageUtilities::encode(WTF::StringView, std::optional<WebCore::ColorSpace>) const"
    )

    assert split == (
        "WebCore::ImageUtilities",
        "encode(WTF::StringView, std::optional<WebCore::ColorSpace>) const",
    )


def test_parse_targets_preserves_overloaded_signatures():
    rows = parse_targets(
        """## Campaign 1 — overload regression

### ImageUtilities (Source/WebCore/platform/graphics/cg)

WebCore::encode(PixelBuffer)                               # HEAP_OVERFLOW — 4-byte walk can run past tail
WebCore::encode(CGImageRef)                               # UAF — callback captures raw ScopedLambda*
WebCore::ImageUtilities::encode(WTF::StringView) const    # OOB_READ — namespaced param type must not split class
"""
    )

    assert rows == [
        {
            "target_class": "WebCore",
            "target_method": "encode(PixelBuffer)",
            "bug_class_hint": "HEAP_OVERFLOW",
            "reason": "4-byte walk can run past tail",
            "campaign": "1 overload regression",
            "sub_area": "ImageUtilities",
            "source_path": "Source/WebCore/platform/graphics/cg",
        },
        {
            "target_class": "WebCore",
            "target_method": "encode(CGImageRef)",
            "bug_class_hint": "UAF",
            "reason": "callback captures raw ScopedLambda*",
            "campaign": "1 overload regression",
            "sub_area": "ImageUtilities",
            "source_path": "Source/WebCore/platform/graphics/cg",
        },
        {
            "target_class": "WebCore::ImageUtilities",
            "target_method": "encode(WTF::StringView) const",
            "bug_class_hint": "OOB_READ",
            "reason": "namespaced param type must not split class",
            "campaign": "1 overload regression",
            "sub_area": "ImageUtilities",
            "source_path": "Source/WebCore/platform/graphics/cg",
        },
    ]

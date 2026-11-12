# Image Codec Bounds Patterns

WebKit image decoders are a historically rich OOB attack surface. Every
width × height × bpp computation is a potential HEAP_OVERFLOW.

## The canonical bug shape

1. Image header declares width=W, height=H
2. Decoder computes bufferSize = W * H * bytesPerPixel (in 32-bit or without overflow check)
3. Buffer allocated with small (overflowed) size
4. Decode loop writes W*H*bpp bytes into the undersized buffer → HEAP_OVERFLOW

## Affected decoders and audit anchors

| Decoder | Directory | Size computation | Anchors |
|---------|-----------|-----------------|---------|
| PNG | Source/WebCore/platform/image-decoders/png/ | `rowBytes * height` | `png_get_rowbytes`, `setSize` |
| JPEG | Source/WebCore/platform/image-decoders/jpeg/ | `width * height * 4` | `outputScanlines`, `setSize` |
| WebP | Source/WebCore/platform/image-decoders/webp/ | `WebPDecodeRGBA` output size | `WebPGetInfo` |
| AVIF | Source/WebCore/platform/image-decoders/avif/ | plane sizes from avifImage | `avifImageGetBuffer` |
| GIF | Source/WebCore/platform/image-decoders/gif/ | frame rect within canvas | `frameRect`, `setSize` |
| ICO/BMP | Source/WebCore/platform/image-decoders/bmp/ | rowBytes from biWidth | `readInfoHeader` |
| ICC profile | Source/WebCore/platform/graphics/cg/ | tag offset + tag size | `tagOffset`, `tagSize`, `profileSize` |
| 3D model | Source/WebCore/Modules/model/ | vertex data size | `replaceVertexData` |

## Video frame sizes

| Format | Planes | Size formula |
|--------|:---:|---|
| NV12 | 2 | Y: stride×height, UV: stride×(height/2) |
| I420 | 3 | Y: stride×height, U,V: (stride/2)×(height/2) |
| BGRA | 1 | stride × height × 4 |

Always verify `stride ≥ width × bytesPerPixel` and `bufferSize ≥ stride × height`.

## WebGL texture uploads

`texImage2D(target, level, internalformat, width, height, border, format, type, pixels)`
- `width × height × bytesPerPixel(format, type)` must ≤ `pixels.byteLength`
- `type` drives bytesPerPixel: UNSIGNED_BYTE=1, FLOAT=4, HALF_FLOAT=2
- `format` drives components: RGBA=4, RGB=3, LUMINANCE_ALPHA=2

## ICC color profile

```cpp
// ❌ tag offset + tag size can overflow uint32
uint32_t end = tagOffset + tagSize;  // wraps if sum > 2^32
if (end <= profileSize) ...

// ✅ safe
if (tagSize > profileSize || tagOffset > profileSize - tagSize) ...
```

"""Validate the exact metadata-free RGBA PNG formats used by this release."""
import struct
import zlib

PNG_SIZES = {
    "assets/architecture.png": (1440, 820),
    "assets/banner.png": (1600, 500),
    "assets/logo.png": (256, 256),
    "assets/social-preview.png": (1280, 640),
}


def validate_png(name, data):
    width, height = PNG_SIZES[name]
    if len(data) > 1048576 or not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError(f"Invalid PNG signature or size: {name}")
    offset = 8
    compressed = bytearray()
    while offset + 12 <= len(data):
        length, kind = struct.unpack_from(">I4s", data, offset)
        end = offset + 12 + length
        if end > len(data):
            break
        payload = data[offset + 8:end - 4]
        checksum, = struct.unpack_from(">I", data, end - 4)
        if checksum != zlib.crc32(kind + payload):
            raise ValueError(f"Invalid PNG checksum: {name}")
        if offset == 8:
            expected = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
            if kind != b"IHDR" or payload != expected:
                raise ValueError(f"Unexpected PNG header: {name}")
        elif kind == b"IDAT":
            compressed.extend(payload)
        elif kind == b"IEND" and end == len(data) and not payload:
            break
        else:
            raise ValueError(f"Unexpected PNG chunk or metadata: {name}")
        offset = end
    else:
        raise ValueError(f"Missing PNG end: {name}")
    if offset + 12 != len(data) or data[offset + 4:offset + 8] != b"IEND":
        raise ValueError(f"Invalid PNG ending: {name}")
    stride = 1 + width * 4
    try:
        inflater = zlib.decompressobj()
        pixels = inflater.decompress(compressed, stride * height + 1)
    except zlib.error as error:
        raise ValueError(f"Invalid PNG compression: {name}") from error
    if (len(pixels) != stride * height or not inflater.eof or inflater.unused_data
            or any(value > 4 for value in pixels[::stride])):
        raise ValueError(f"Invalid PNG scanlines: {name}")

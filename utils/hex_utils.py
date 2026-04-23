"""Hex formatting helpers — xxd-compatible output."""


def extract_hex_preview(filepath: str, num_bytes: int = 64) -> list[dict]:
    """
    Read the first `num_bytes` of a file and format as xxd-style rows.
    Each row: { "address": "0x0000", "hex": "XX XX ...", "ascii": "....." }
    Non-printable bytes rendered as '.'
    """
    rows = []
    try:
        with open(filepath, 'rb') as f:
            data = f.read(num_bytes)
        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            hex_str = ' '.join(f'{b:02X}' for b in chunk)
            hex_str = hex_str.ljust(47)  # pad to 16-byte alignment
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            rows.append({
                "address": f"0x{offset:04X}",
                "hex": hex_str,
                "ascii": ascii_str,
            })
    except Exception:
        pass
    return rows
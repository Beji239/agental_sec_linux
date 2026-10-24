# modules/remote/qr.py
# A small QR code maker for the authenticator link: byte mode, error
# correction level M, versions 1 to 10. Enough for an otpauth:// link.

# Per version: (error correction codewords per block, number of blocks).
_BLOCKS = {1: (10, 1), 2: (16, 1), 3: (26, 1), 4: (18, 2), 5: (24, 2),
           6: (16, 4), 7: (18, 4), 8: (22, 4), 9: (22, 5), 10: (26, 5)}
_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
          7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}
_LEVEL_M = 0


def _raw_codewords(ver: int) -> int:
    bits = (16 * ver + 128) * ver + 64
    if ver >= 2:
        n = ver // 7 + 2
        bits -= (25 * n - 10) * n - 55
        if ver >= 7:
            bits -= 36
    return bits // 8


def _data_codewords(ver: int) -> int:
    ecc, blocks = _BLOCKS[ver]
    return _raw_codewords(ver) - ecc * blocks


def _gf_mul(x: int, y: int) -> int:
    z = 0
    for i in range(7, -1, -1):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree: int) -> list:
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 0x02)
    return result


def _rs_remainder(data: list, divisor: list) -> list:
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


def _codewords(data: bytes) -> tuple:
    for ver in range(1, 11):
        count_bits = 8 if ver < 10 else 16
        if 4 + count_bits + 8 * len(data) <= _data_codewords(ver) * 8:
            break
    else:
        raise ValueError("too long for a QR code this small")
    bits = [0, 1, 0, 0]
    bits += [(len(data) >> i) & 1 for i in range(count_bits - 1, -1, -1)]
    for b in data:
        bits += [(b >> i) & 1 for i in range(7, -1, -1)]
    cap = _data_codewords(ver) * 8
    bits += [0] * min(4, cap - len(bits))
    bits += [0] * (-len(bits) % 8)
    words = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(words) < cap // 8:
        words.append(pad)
        pad ^= 0xEC ^ 0x11

    ecc_len, nblocks = _BLOCKS[ver]
    raw = _raw_codewords(ver)
    short = nblocks - raw % nblocks
    short_len = raw // nblocks
    div = _rs_divisor(ecc_len)
    blocks, k = [], 0
    for i in range(nblocks):
        n = short_len - ecc_len + (0 if i < short else 1)
        dat = words[k:k + n]
        k += n
        ecc = _rs_remainder(dat, div)
        if i < short:
            dat = dat + [0]
        blocks.append(dat + ecc)
    out = []
    for i in range(len(blocks[0])):
        for j, blk in enumerate(blocks):
            if i != short_len - ecc_len or j >= short:
                out.append(blk[i])
    return ver, out


def _mask_hit(mask: int, x: int, y: int) -> bool:
    return [
        (x + y) % 2 == 0, y % 2 == 0, x % 3 == 0, (x + y) % 3 == 0,
        (x // 3 + y // 2) % 2 == 0, x * y % 2 + x * y % 3 == 0,
        (x * y % 2 + x * y % 3) % 2 == 0, ((x + y) % 2 + x * y % 3) % 2 == 0,
    ][mask]


class _Grid:
    def __init__(self, ver: int):
        self.ver = ver
        self.size = ver * 4 + 17
        self.dark = [[False] * self.size for _ in range(self.size)]
        self.fixed = [[False] * self.size for _ in range(self.size)]

    def put(self, x, y, dark):
        self.dark[y][x] = bool(dark)
        self.fixed[y][x] = True

    def patterns(self):
        n = self.size
        for i in range(n):
            self.put(6, i, i % 2 == 0)
            self.put(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (n - 4, 3), (3, n - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < n and 0 <= y < n:
                        self.put(x, y, max(abs(dx), abs(dy)) not in (2, 4))
        pos = _ALIGN[self.ver]
        last = len(pos) - 1
        for i, ax in enumerate(pos):
            for j, ay in enumerate(pos):
                if (i, j) in ((0, 0), (0, last), (last, 0)):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self.put(ax + dx, ay + dy, max(abs(dx), abs(dy)) != 1)
        self.format_bits(0)
        if self.ver >= 7:
            rem = self.ver
            for _ in range(12):
                rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
            bits = self.ver << 12 | rem
            for i in range(18):
                bit = (bits >> i) & 1
                a, b = n - 11 + i % 3, i // 3
                self.put(a, b, bit)
                self.put(b, a, bit)

    def format_bits(self, mask: int):
        data = _LEVEL_M << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412
        bit = lambda i: (bits >> i) & 1
        n = self.size
        for i in range(6):
            self.put(8, i, bit(i))
        self.put(8, 7, bit(6))
        self.put(8, 8, bit(7))
        self.put(7, 8, bit(8))
        for i in range(9, 15):
            self.put(14 - i, 8, bit(i))
        for i in range(8):
            self.put(n - 1 - i, 8, bit(i))
        for i in range(8, 15):
            self.put(8, n - 15 + i, bit(i))
        self.put(8, n - 8, True)

    def place(self, words: list):
        n, i, total = self.size, 0, len(words) * 8
        right = n - 1
        while right >= 1:
            if right == 6:
                right = 5
            upward = ((right + 1) & 2) == 0
            for vert in range(n):
                y = n - 1 - vert if upward else vert
                for x in (right, right - 1):
                    if not self.fixed[y][x]:
                        if i < total:
                            self.dark[y][x] = bool((words[i >> 3] >> (7 - (i & 7))) & 1)
                        i += 1
            right -= 2

    def apply_mask(self, mask: int):
        for y in range(self.size):
            for x in range(self.size):
                if not self.fixed[y][x] and _mask_hit(mask, x, y):
                    self.dark[y][x] = not self.dark[y][x]

    def penalty(self) -> int:
        n, d, score = self.size, self.dark, 0
        lines = d + [list(col) for col in zip(*d)]
        for line in lines:
            run, prev = 0, None
            for v in line:
                if v == prev:
                    run += 1
                else:
                    if run >= 5:
                        score += run - 2
                    run, prev = 1, v
            if run >= 5:
                score += run - 2
            text = "".join("1" if v else "0" for v in line)
            for pat in ("10111010000", "00001011101"):
                score += 40 * sum(1 for k in range(len(text) - 10)
                                  if text.startswith(pat, k))
        for y in range(n - 1):
            for x in range(n - 1):
                if d[y][x] == d[y][x + 1] == d[y + 1][x] == d[y + 1][x + 1]:
                    score += 3
        dark = sum(map(sum, d))
        score += abs(dark * 20 - n * n * 10) // (n * n) * 10
        return score


def matrix(text: str) -> list:
    """The code as rows of True (dark) and False."""
    ver, words = _codewords(text.encode("utf-8"))
    best, best_score = None, None
    for mask in range(8):
        g = _Grid(ver)
        g.patterns()
        g.place(words)
        g.apply_mask(mask)
        g.format_bits(mask)
        score = g.penalty()
        if best_score is None or score < best_score:
            best, best_score = g, score
    return best.dark


def svg(text: str, scale: int = 6, border: int = 4) -> str:
    rows = matrix(text)
    n = len(rows) + 2 * border
    parts = [f"M{x + border},{y + border}h1v1h-1z"
             for y, row in enumerate(rows) for x, v in enumerate(row) if v]
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" '
            f'width="{n * scale}" height="{n * scale}" shape-rendering="crispEdges">'
            f'<rect width="{n}" height="{n}" fill="#fff"/>'
            f'<path d="{"".join(parts)}" fill="#000"/></svg>')

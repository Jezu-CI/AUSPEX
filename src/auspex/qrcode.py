"""Générateur de QR codes (ISO/IEC 18004), sans dépendance.

Sert à afficher l'adresse otpauth:// lors de l'inscription à la double
authentification : l'image NetBox se construit hors ligne, sans bibliothèque
à télécharger. Mode octets, toutes versions (1 à 40), correction L ou M,
choix du masque par les pénalités de la norme.

Vérifié par les valeurs de référence de la norme (Reed-Solomon, bits de format
et de version) et, en CI, en relisant les QR codes avec un vrai décodeur.
"""

from __future__ import annotations

# Index = version (0 inutilisé). Tables de la norme, niveaux L et M.
_ECC_PER_BLOCK = {
    "L": (-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28,
          28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    "M": (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
          26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),
}
_NUM_BLOCKS = {
    "L": (-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8,
          8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25),
    "M": (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
          17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49),
}
_FORMAT_ECL = {"L": 1, "M": 0}


class QRError(ValueError):
    pass


# --- Reed-Solomon sur GF(256), polynôme 0x11D -------------------------------------

def _gf_mul(x: int, y: int) -> int:
    z = 0
    for i in range(7, -1, -1):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def rs_divisor(degree: int) -> list[int]:
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 0x02)
    return result


def rs_remainder(data: list[int], divisor: list[int]) -> list[int]:
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


# --- Capacités ---------------------------------------------------------------------

def _raw_modules(ver: int) -> int:
    result = (16 * ver + 128) * ver + 64
    if ver >= 2:
        n = ver // 7 + 2
        result -= (25 * n - 10) * n - 55
        if ver >= 7:
            result -= 36
    return result


def data_codewords(ver: int, ecl: str) -> int:
    return _raw_modules(ver) // 8 - _ECC_PER_BLOCK[ecl][ver] * _NUM_BLOCKS[ecl][ver]


def format_bits(ecl: str, mask: int) -> int:
    data = _FORMAT_ECL[ecl] << 3 | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return (data << 10 | rem) ^ 0x5412


def version_bits(ver: int) -> int:
    rem = ver
    for _ in range(12):
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
    return ver << 12 | rem


def _alignment_positions(ver: int) -> list[int]:
    if ver == 1:
        return []
    n = ver // 7 + 2
    size = ver * 4 + 17
    step = (ver * 8 + n * 3 + 5) // (n * 4 - 4) * 2
    return [6] + sorted(size - 7 - i * step for i in range(n - 1))


# --- Construction ------------------------------------------------------------------

_MASKS = (
    lambda x, y: (x + y) % 2 == 0,
    lambda x, y: y % 2 == 0,
    lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: x * y % 2 + x * y % 3 == 0,
    lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
)


class _Grid:
    def __init__(self, ver: int):
        self.ver = ver
        self.size = ver * 4 + 17
        self.mod = [[False] * self.size for _ in range(self.size)]
        self.fn = [[False] * self.size for _ in range(self.size)]

    def set_fn(self, x: int, y: int, dark: bool) -> None:
        self.mod[y][x] = dark
        self.fn[y][x] = True

    def function_patterns(self) -> None:
        s = self.size
        for i in range(s):
            self.set_fn(6, i, i % 2 == 0)
            self.set_fn(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (s - 4, 3), (3, s - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < s and 0 <= y < s:
                        self.set_fn(x, y, max(abs(dx), abs(dy)) not in (2, 4))
        pos = _alignment_positions(self.ver)
        last = len(pos) - 1
        for i, ax in enumerate(pos):
            for j, ay in enumerate(pos):
                if (i, j) in ((0, 0), (0, last), (last, 0)):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self.set_fn(ax + dx, ay + dy, max(abs(dx), abs(dy)) != 1)
        self.draw_format(0, "M")  # réserve les emplacements ; réécrit avec le vrai masque
        if self.ver >= 7:
            bits = version_bits(self.ver)
            for i in range(18):
                dark = (bits >> i) & 1 == 1
                a, b = s - 11 + i % 3, i // 3
                self.set_fn(a, b, dark)
                self.set_fn(b, a, dark)

    def draw_format(self, mask: int, ecl: str) -> None:
        bits = format_bits(ecl, mask)
        bit = lambda i: (bits >> i) & 1 == 1  # noqa: E731
        s = self.size
        for i in range(6):
            self.set_fn(8, i, bit(i))
        self.set_fn(8, 7, bit(6))
        self.set_fn(8, 8, bit(7))
        self.set_fn(7, 8, bit(8))
        for i in range(9, 15):
            self.set_fn(14 - i, 8, bit(i))
        for i in range(8):
            self.set_fn(s - 1 - i, 8, bit(i))
        for i in range(8, 15):
            self.set_fn(8, s - 15 + i, bit(i))
        self.set_fn(8, s - 8, True)  # module toujours sombre

    def draw_codewords(self, data: list[int]) -> None:
        s = self.size
        i = 0
        right = s - 1
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(s):
                for j in range(2):
                    x = right - j
                    upward = ((right + 1) & 2) == 0
                    y = s - 1 - vert if upward else vert
                    if not self.fn[y][x] and i < len(data) * 8:
                        self.mod[y][x] = (data[i >> 3] >> (7 - (i & 7))) & 1 == 1
                        i += 1
            right -= 2

    def apply_mask(self, mask: int) -> None:
        f = _MASKS[mask]
        for y in range(self.size):
            for x in range(self.size):
                if not self.fn[y][x] and f(x, y):
                    self.mod[y][x] = not self.mod[y][x]

    def penalty(self) -> int:
        s, m = self.size, self.mod
        score = 0
        lines = [m[y] for y in range(s)] + [[m[y][x] for y in range(s)] for x in range(s)]
        pattern_a = [True, False, True, True, True, False, True, False, False, False, False]
        pattern_b = pattern_a[::-1]
        for line in lines:
            run, prev = 0, None
            for v in line:
                if v == prev:
                    run += 1
                else:
                    if run >= 5:
                        score += 3 + run - 5
                    run, prev = 1, v
            if run >= 5:
                score += 3 + run - 5
            for k in range(len(line) - 10):
                window = line[k:k + 11]
                if window == pattern_a or window == pattern_b:
                    score += 40
        for y in range(s - 1):
            for x in range(s - 1):
                if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                    score += 3
        dark = sum(sum(row) for row in m)
        score += 10 * int(abs(dark * 100 / (s * s) - 50) // 5)
        return score


def _codewords(data: bytes, ver: int, ecl: str) -> list[int]:
    cc_bits = 8 if ver <= 9 else 16
    bits: list[int] = []

    def put(value: int, n: int) -> None:
        bits.extend((value >> i) & 1 for i in range(n - 1, -1, -1))

    put(0b0100, 4)
    put(len(data), cc_bits)
    for b in data:
        put(b, 8)
    capacity = data_codewords(ver, ecl) * 8
    put(0, min(4, capacity - len(bits)))
    put(0, -len(bits) % 8)
    words = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(words) < capacity // 8:
        words.append(pad)
        pad ^= 0xEC ^ 0x11

    nblocks, ecc_len = _NUM_BLOCKS[ecl][ver], _ECC_PER_BLOCK[ecl][ver]
    raw = _raw_modules(ver) // 8
    n_short = nblocks - raw % nblocks
    short_len = raw // nblocks
    divisor = rs_divisor(ecc_len)
    blocks, k = [], 0
    for i in range(nblocks):
        dat = words[k:k + short_len - ecc_len + (0 if i < n_short else 1)]
        k += len(dat)
        ecc = rs_remainder(dat, divisor)
        if i < n_short:
            dat = dat + [0]
        blocks.append(dat + ecc)
    out = []
    for i in range(len(blocks[0])):
        for j, blk in enumerate(blocks):
            if i != short_len - ecc_len or j >= n_short:
                out.append(blk[i])
    return out


def encode(text: str | bytes, ecl: str = "M", mask: int | None = None) -> list[list[bool]]:
    """Matrice du QR code (True = module sombre), sans marge."""
    if ecl not in _ECC_PER_BLOCK:
        raise QRError("niveau de correction : L ou M")
    data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
    for ver in range(1, 41):
        needed = 4 + (8 if ver <= 9 else 16) + 8 * len(data)
        if needed <= data_codewords(ver, ecl) * 8:
            break
    else:
        raise QRError("texte trop long pour un QR code")
    words = _codewords(data, ver, ecl)
    grid = _Grid(ver)
    grid.function_patterns()
    grid.draw_codewords(words)
    if mask is None:
        best = None
        for m in range(8):
            grid.apply_mask(m)
            grid.draw_format(m, ecl)
            p = grid.penalty()
            if best is None or p < best[0]:
                best = (p, m)
            grid.apply_mask(m)  # le masque s'annule en le réappliquant
        mask = best[1]
    grid.apply_mask(mask)
    grid.draw_format(mask, ecl)
    return grid.mod


def to_svg(matrix: list[list[bool]], border: int = 4, size_px: int = 220) -> str:
    """SVG autonome : modules noirs sur fond blanc (y compris en mode sombre,
    sinon les téléphones ne le lisent pas)."""
    n = len(matrix) + 2 * border
    path = "".join(f"M{x + border} {y + border}h1v1h-1z"
                   for y, row in enumerate(matrix) for x, dark in enumerate(row) if dark)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" width="{size_px}" '
            f'height="{size_px}" shape-rendering="crispEdges" role="img" aria-label="QR code">'
            f'<rect width="{n}" height="{n}" fill="#fff"/><path d="{path}" fill="#000"/></svg>')

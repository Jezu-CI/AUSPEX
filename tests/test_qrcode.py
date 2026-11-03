"""Générateur de QR codes : valeurs de référence, structure, et relecture par un
vrai décodeur (zxing-cpp, installé avec les dépendances de développement)."""

import pytest

from auspex import qrcode as qr


# --- Valeurs de référence --------------------------------------------------------------

def test_reed_solomon_reference():
    """Exemple classique « HELLO WORLD », version 1-M."""
    data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17]
    assert qr.rs_remainder(data, qr.rs_divisor(10)) == [196, 35, 39, 119, 235, 215, 231, 226, 93, 23]


@pytest.mark.parametrize("ecl,mask,expected", [
    ("M", 0, "101010000010010"), ("M", 1, "101000100100101"), ("M", 2, "101111001111100"),
    ("M", 3, "101101101001011"), ("M", 4, "100010111111001"), ("M", 5, "100000011001110"),
    ("M", 6, "100111110010111"), ("M", 7, "100101010100000"), ("L", 0, "111011111000100"),
])
def test_format_bits(ecl, mask, expected):
    assert format(qr.format_bits(ecl, mask), "015b") == expected


def test_version_bits():
    assert format(qr.version_bits(7), "018b") == "000111110010010100"
    assert format(qr.version_bits(40), "018b") == "101000110001101001"


@pytest.mark.parametrize("ver,ecl,expected", [(1, "M", 16), (5, "M", 86), (10, "M", 216),
                                              (1, "L", 19), (40, "L", 2956), (40, "M", 2334)])
def test_capacities(ver, ecl, expected):
    assert qr.data_codewords(ver, ecl) == expected


# --- Structure ---------------------------------------------------------------------------

OTPAUTH = ("otpauth://totp/Auspex%3Auser1?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
           "&issuer=Auspex&algorithm=SHA1&digits=6&period=30")


def test_finder_patterns_and_timing():
    m = qr.encode(OTPAUTH)
    n = len(m)
    assert (n - 17) % 4 == 0
    finder = [[max(abs(dx), abs(dy)) not in (2, 4) for dx in range(-3, 4)] for dy in range(-3, 4)]
    for ox, oy in ((0, 0), (n - 7, 0), (0, n - 7)):
        assert [row[ox:ox + 7] for row in m[oy:oy + 7]] == finder
    assert [m[6][x] for x in range(8, n - 8)] == [x % 2 == 0 for x in range(8, n - 8)]
    assert m[n - 8][8] is True  # module toujours sombre


def test_version_grows_with_length():
    assert len(qr.encode("a")) == 21
    assert len(qr.encode("a" * 200)) > len(qr.encode("a" * 50))
    with pytest.raises(qr.QRError):
        qr.encode("a" * 3000)


def test_svg():
    svg = qr.to_svg(qr.encode("test"))
    assert svg.startswith("<svg") and 'fill="#fff"' in svg and "<script" not in svg


# --- Relecture par un vrai décodeur ---------------------------------------------------------

@pytest.fixture
def decode():
    zxingcpp = pytest.importorskip("zxingcpp", reason="zxing-cpp absent (installé en CI)")
    np = pytest.importorskip("numpy")

    def run(matrix, scale=6, border=4):
        n = len(matrix) + 2 * border
        img = np.full((n * scale, n * scale), 255, dtype=np.uint8)
        for y, row in enumerate(matrix):
            for x, dark in enumerate(row):
                if dark:
                    Y, X = (y + border) * scale, (x + border) * scale
                    img[Y:Y + scale, X:X + scale] = 0
        return [r.text for r in zxingcpp.read_barcodes(img)]
    return run


@pytest.mark.parametrize("text", [
    "a", "Auspex", OTPAUTH,
    OTPAUTH.replace("user1", "prenom.nom-tres-long%40ministere.gouv.fr"),
    "x" * 150, "é" * 120,          # versions ≥ 7 : bits de version
    "y" * 400,                      # plusieurs blocs de tailles différentes
])
def test_decodes(decode, text):
    assert decode(qr.encode(text)) == [text]


@pytest.mark.parametrize("mask", range(8))
def test_all_masks_decode(decode, mask):
    assert decode(qr.encode(OTPAUTH, mask=mask)) == [OTPAUTH]


def test_level_l_decodes(decode):
    assert decode(qr.encode(OTPAUTH, ecl="L")) == [OTPAUTH]

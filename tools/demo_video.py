#!/usr/bin/env python3
"""Vidéo de démonstration d'Auspex (workflow « Vidéo de démonstration »).

Parcours filmé sur un vrai central chargé du scénario de démonstration : connexion
avec double authentification, tableau de bord, écarts (dont un poste qui administre
le contrôleur de domaine), carte, rapport d'audit NIS2. Sous-titres en français
incrustés dans la page, curseur visible.

Prérequis : ceux de tools/captures.py (central installé, premier cycle passé).
Usage (dans deploy/) : python ../tools/demo_video.py
Résultat : demo/auspex-demo.webm (converti en MP4 par le workflow).
"""

from __future__ import annotations

import base64
import html
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import yaml
from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
import captures  # noqa: E402
from ci_mfa import ENV, URL, mfa  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OUT = Path("demo")
SIZE = {"width": 1280, "height": 720}     # taille de la vidéo
# Fenêtre du navigateur plus petite que la vidéo : la page est agrandie d'environ 20 %,
# textes et tableaux restent lisibles une fois la vidéo réduite sur un site ou un téléphone.
VIEW = {"width": 1066, "height": 600}
ENROLLED_PERIOD = 0

# Sous-titres et curseur, réinjectés à chaque page (la vidéo ne montre pas la souris).
INIT = """
(() => {
  const css = `
    #ax-cap{position:fixed;left:50%;bottom:28px;transform:translateX(-50%);max-width:1040px;
      background:rgba(18,25,28,.92);color:#fff;font:600 22px/1.4 system-ui,Segoe UI,Roboto,sans-serif;
      padding:14px 26px;border-radius:12px;border-left:6px solid #3ddc84;z-index:2147483647;
      box-shadow:0 8px 30px rgba(0,0,0,.35);opacity:0;transition:opacity .35s;pointer-events:none}
    #ax-cap.on{opacity:1}
    #ax-cur{position:fixed;width:22px;height:22px;margin:-11px 0 0 -11px;border-radius:50%;
      background:rgba(61,220,132,.35);border:2px solid #12805a;z-index:2147483647;pointer-events:none;
      transition:transform .12s;left:-50px;top:-50px}
    #ax-cur.click{transform:scale(1.8)}`;
  const add = () => {
    if (document.getElementById('ax-cur')) return;
    const s = document.createElement('style'); s.textContent = css; document.documentElement.appendChild(s);
    const c = document.createElement('div'); c.id = 'ax-cur'; document.documentElement.appendChild(c);
    const b = document.createElement('div'); b.id = 'ax-cap'; document.documentElement.appendChild(b);
  };
  document.addEventListener('DOMContentLoaded', add); if (document.readyState !== 'loading') add();
  addEventListener('mousemove', e => { const c = document.getElementById('ax-cur');
    if (c) { c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px'; } }, true);
  addEventListener('mousedown', () => { const c = document.getElementById('ax-cur');
    if (c) c.classList.add('click'); }, true);
  addEventListener('mouseup', () => { const c = document.getElementById('ax-cur');
    if (c) c.classList.remove('click'); }, true);
  window.axCaption = (t) => { add(); const b = document.getElementById('ax-cap');
    if (!t) { b.classList.remove('on'); return; } b.textContent = t; b.classList.add('on'); };
})();
"""


class Film:
    def __init__(self, page):
        self.page = page
        self.mouse = (640, 360)

    def ensure(self) -> None:
        """Sous-titres et curseur présents (une page créée par set_content n'exécute pas
        le script d'initialisation)."""
        if not self.page.evaluate("() => !!window.axCaption"):
            self.page.evaluate(INIT)
            self.page.mouse.move(*self.mouse)

    def say(self, text: str, seconds: float) -> None:
        """Affiche un sous-titre et laisse le temps de le lire."""
        self.ensure()
        self.page.evaluate("t => window.axCaption(t)", text)
        time.sleep(seconds)

    def quiet(self) -> None:
        self.page.evaluate("() => window.axCaption && window.axCaption('')")
        time.sleep(0.4)

    def move(self, locator) -> tuple[float, float]:
        self.ensure()
        box = locator.bounding_box()
        x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
        self.page.mouse.move(x, y, steps=28)
        self.mouse = (x, y)
        time.sleep(0.25)
        return x, y

    def click(self, locator) -> None:
        locator.scroll_into_view_if_needed()
        self.move(locator)
        locator.click()

    def type(self, locator, text: str, secret: bool = False) -> None:
        self.click(locator)
        locator.press_sequentially(text, delay=25 if secret else 70)

    def goto(self, url: str) -> None:
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")
        self.page.mouse.move(*self.mouse)

    def scroll(self, pixels: int, seconds: float = 2.5) -> None:
        steps = 30
        for _ in range(steps):
            self.page.mouse.wheel(0, pixels / steps)
            time.sleep(seconds / steps)

    def card(self, title: str, subtitle: str, seconds: float, extra: str = "",
             signature: bool = False) -> None:
        """Carte titre plein écran. signature=True ajoute en bas la signature Jezu-CI."""
        icon = (ROOT / "site/assets/auspex-icon.svg").read_text(encoding="utf-8")
        sig = ""
        if signature:
            logo = (ROOT / "site/assets/jezu-ci-signature.svg").read_text(encoding="utf-8")
            sig = f'<div class="sig"><span>un projet</span>{logo}</div>'
        self.page.set_content(f"""<!doctype html><html><head><meta charset="utf-8"><style>
          body{{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
          background:#12191c;color:#e8eef0;font-family:system-ui,Segoe UI,Roboto,sans-serif;text-align:center}}
          h1{{font-size:64px;margin:18px 0 8px}} p{{font-size:26px;color:#3ddc84;margin:0 0 10px}}
          small{{font-size:19px;color:#9fb0b6}} .i svg{{width:120px;height:120px}}
          .sig{{position:fixed;left:0;right:0;bottom:34px;display:flex;align-items:center;
          justify-content:center;gap:2px;color:#9fb0b6;font-size:18px}}
          .sig svg{{width:auto;height:68px}}</style></head>
          <body><div><div class="i">{icon}</div><h1>{html.escape(title)}</h1><p>{html.escape(subtitle)}</p>
          {extra}</div>{sig}</body></html>""")
        time.sleep(seconds)

    def schema(self, svg: Path, caption: str, seconds: float) -> None:
        self.page.set_content(f"""<!doctype html><html><head><meta charset="utf-8"><style>
          body{{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#fff}}
          img{{max-width:92vw;max-height:70vh}}</style></head>
          <body><img src="data:image/svg+xml;base64,{base64.b64encode(svg.read_bytes()).decode()}">
          </body></html>""")
        time.sleep(0.5)
        self.say(caption, seconds)


def enroll_admin(browser) -> str:
    """Inscription du compte admin à la double authentification, HORS caméra : la vidéo
    publique ne montre ni QR code, ni clé, ni codes de secours (même d'un central jetable)."""
    ctx = browser.new_context(viewport=VIEW, extra_http_headers={"X-Forwarded-For": captures.CLIENT})
    p = ctx.new_page()
    captures.login(p, "admin", ENV["NETBOX_ADMIN_PASSWORD"])
    secret = captures.totp_from_page(p)
    captures.submit_code(p, mfa.totp(secret))
    ctx.close()
    global ENROLLED_PERIOD
    ENROLLED_PERIOD = int(time.time()) // 30
    return secret


def admin_login(f: Film, secret: str) -> None:
    p = f.page
    f.goto(f"{URL}/login/?next=/")
    f.say("Auspex se consulte dans NetBox, depuis un navigateur.", 3)
    f.type(p.locator("input[name=username]"), "admin")
    f.type(p.locator("input[name=password]"), ENV["NETBOX_ADMIN_PASSWORD"], secret=True)
    f.click(p.locator("form button[type=submit]").last)
    p.wait_for_load_state("networkidle")
    f.say("Double authentification obligatoire : application de codes, e-mail, clé de sécurité ou carte à puce.", 3)
    while int(time.time()) // 30 <= ENROLLED_PERIOD:   # code d'une autre période (anti-rejeu)
        time.sleep(0.5)
    f.type(p.locator("#code"), mfa.totp(secret))
    f.click(p.locator("form button[type=submit]").last)
    p.wait_for_load_state("networkidle")
    f.quiet()


def run() -> None:
    OUT.mkdir(exist_ok=True)
    captures.configure()
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        secret = enroll_admin(browser)
        ctx = browser.new_context(viewport=VIEW, locale="fr-FR", record_video_dir=str(OUT / "brut"),
                                  record_video_size=SIZE,
                                  extra_http_headers={"X-Forwarded-For": captures.CLIENT})
        ctx.add_init_script(INIT)
        ctx.add_init_script("try { localStorage.setItem('netbox-color-mode', 'light'); } catch (e) {}")
        page = ctx.new_page()
        f = Film(page)
        try:
            scenes(f, page, secret)
        except Exception:
            page.screenshot(path=str(OUT / "erreur.png"))    # pour comprendre, avec la vidéo partielle
            raise
        finally:
            video = page.video.path()
            ctx.close()
            browser.close()
            shutil.move(video, OUT / "auspex-demo.webm")
            shutil.rmtree(OUT / "brut", ignore_errors=True)
    print(f"Vidéo : {OUT / 'auspex-demo.webm'}", flush=True)


def scenes(f: Film, page, secret: str) -> None:

    # 1. Ouverture
    f.card("Auspex", "La CMDB open source qui se remplit en écoutant le réseau", 4.5,
           "<small>Inventaire des actifs IT et OT · contrôle de la segmentation · preuves NIS2, DORA, IEC 62443</small>")
    schemas = sorted((ROOT / "site/assets/diagrammes").glob("*-clair.svg"))
    home = next((s for s in schemas if "Capteur" in s.read_text(encoding="utf-8")
                 and "Audit" in s.read_text(encoding="utf-8")), schemas[0] if schemas else None)
    if home:
        f.schema(home, "Un capteur écoute une copie du trafic, sans jamais rien émettre. "
                       "Le central analyse et range tout dans NetBox.", 6)

    # 2. Connexion
    admin_login(f, secret)

    # 3. Tableau de bord
    f.goto(f"{URL}/")
    time.sleep(1.5)
    f.say("Le tableau de bord : 7 jours de trafic d'un site IT et industriel de démonstration.", 4)
    f.say("Écarts ouverts par gravité, état du service, inventaire observé…", 3.5)
    f.scroll(900, 3)
    f.say("… et la matrice des zones : en rouge, les communications qui sortent du cadre.", 4.5)
    f.quiet()

    # 4. Écarts
    f.goto(f"{URL}/plugins/auspex/ecarts/")
    f.say("Chaque écart compare ce qui est déclaré à ce qui est réellement observé.", 4)
    recherche = page.locator("#auspex-filters input[name=q]")   # pas la recherche de NetBox
    f.type(recherche, "3389")
    recherche.press("Enter")
    page.wait_for_load_state("networkidle")
    page.mouse.move(*f.mouse)
    f.say("Ici, un poste utilisateur ouvre un bureau à distance sur le contrôleur de domaine : "
          "le modèle d'administration en tiers est violé. Gravité critique.", 6.5)
    f.goto(f"{URL}/plugins/auspex/ecarts/?q=502")
    f.say("Là, un serveur interroge directement un automate en Modbus, sans passer par la DMZ industrielle.", 5.5)
    f.quiet()

    # 5. Carte
    f.goto(f"{URL}/plugins/auspex/carte/")
    page.wait_for_selector("#auspex-map.ready", timeout=20000)
    time.sleep(0.8)
    f.say("La carte : l'informatique de gestion à gauche, l'atelier à droite, les flux en écart en rouge.", 5)
    node = page.locator(".auspex-map-svg .node:has(.halo)").first
    f.click(node)
    f.say("Un clic sur un actif : son identification, ses indices, ses écarts et ses flux.", 5)
    page.evaluate("window.auspexMap.clear()")
    f.click(page.locator("#auspex-map-issues"))
    f.say("« Écarts seulement » : ne garde que ce qui pose problème. Idéal en réunion.", 4.5)
    f.quiet()

    # 6. Audit NIS2
    cfg_path = Path("config/auspex.yaml")
    cfg = yaml.safe_load(cfg_path.read_text())
    cfg["organisation"] = "Ville de Démo"
    cfg_path.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    r = subprocess.run(["docker", "compose", "exec", "-T", "auspex", "auspex", "-c", "/etc/auspex/auspex.yaml",
                        "audit", "export", "nis2"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"export d'audit : {r.stdout}{r.stderr}")
    f.goto(f"{URL}/plugins/auspex/audits/")
    f.say("Des rapports d'audit signés, par référentiel : NIS2, DORA, IEC 62443, ISO 27001, ANSSI.", 5)
    archive = max(Path("data/state/tableau/audits").glob("auspex-audit-nis2-*.zip"), key=lambda p: p.stat().st_mtime)
    with zipfile.ZipFile(archive) as z:
        member = next(n for n in z.namelist() if n.endswith("/rapport.html"))
        report = OUT / "rapport-nis2.html"
        report.write_bytes(z.read(member))
    f.goto(report.resolve().as_uri())
    f.say("Un constat par exigence, prêt à remettre à l'auditeur…", 4)
    f.scroll(1100, 4)
    f.say("… et vérifiable sans Auspex : un seul fichier modifié, et la signature ne passe plus.", 5)
    f.quiet()

    # 7. Fin
    f.card("Auspex", "Open source · licence AGPL v3 · conçu par Yann Mathon", 6,
           "<small>Documentation, téléchargement : jezu-ci.github.io/AUSPEX</small>",
           signature=True)



if __name__ == "__main__":
    run()

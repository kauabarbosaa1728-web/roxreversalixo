import json
import math
import struct
import zlib
from functools import lru_cache

from flask import Response, abort


@lru_cache(maxsize=3)
def app_icon(size):
    # Ícone PNG: roteador branco, círculo verde e fundo azul.
    rows = bytearray()

    for y in range(size):
        rows.append(0)

        for x in range(size):
            px = x / size
            py = y / size
            color = (16, 45, 64)

            distance = math.hypot(
                px - 0.5,
                py - 0.5,
            )

            if 0.32 < distance < 0.35:
                color = (28, 190, 158)

            router = (
                0.29 < px < 0.71
                and 0.48 < py < 0.66
            )
            left_antenna = (
                0.33 < px < 0.37
                and 0.32 < py < 0.51
            )
            right_antenna = (
                0.63 < px < 0.67
                and 0.32 < py < 0.51
            )

            if router or left_antenna or right_antenna:
                color = (245, 250, 255)

            if (
                0.33 < px < 0.46
                and 0.56 < py < 0.60
            ):
                color = (16, 45, 64)

            if math.hypot(
                px - 0.61,
                py - 0.58,
            ) < 0.022:
                color = (8, 125, 114)

            rows.extend(color)

    def chunk(kind, data):
        checksum = zlib.crc32(kind + data) & 0xffffffff

        return (
            struct.pack("!I", len(data))
            + kind
            + data
            + struct.pack("!I", checksum)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(
            b"IHDR",
            struct.pack(
                "!2I5B",
                size, size, 8, 2, 0, 0, 0,
            ),
        )
        + chunk(
            b"IDAT",
            zlib.compress(bytes(rows), 9),
        )
        + chunk(b"IEND", b"")
    )


OFFLINE = """
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Reversa · Sem conexão</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #102d40;
      color: white;
      font: 18px system-ui;
    }

    main {
      max-width: 420px;
      padding: 28px;
    }

    button {
      background: #087d72;
      color: white;
      padding: 14px 22px;
      border: 0;
      border-radius: 10px;
      font: inherit;
    }
  </style>
</head>
<body>
  <main>
    <h1>Sem conexão</h1>
    <p>
      Confira sua internet e tente novamente.
      Para consultar ou salvar equipamentos,
      o aplicativo precisa estar conectado ao sistema.
    </p>
    <button onclick="location.reload()">
      Tentar novamente
    </button>
  </main>
</body>
</html>
"""


WORKER = """
const CACHE = 'reversa-offline-v1';

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE)
      .then(cache => cache.add('/offline.html'))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys
          .filter(key =>
            key.startsWith('reversa-offline-') && key !== CACHE
          )
          .map(key => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  // Formulários e cadastros continuam indo diretamente ao servidor.
  if (
    event.request.method !== 'GET' ||
    event.request.mode !== 'navigate'
  ) {
    return;
  }

  // Não salva páginas com dados ou senhas no cache.
  event.respondWith(
    fetch(event.request).catch(async () => {
      const offlinePage = await caches.match('/offline.html');

      return offlinePage || new Response(
        'Sem conexão. Tente novamente.',
        {
          headers: {
            'Content-Type': 'text/plain; charset=utf-8'
          }
        }
      );
    })
  );
});
"""


SCRIPT = """
let installPrompt = null;

const installButton = document.getElementById('install-app');
const installHelp = document.getElementById('install-help');

const isStandalone = () =>
  window.matchMedia('(display-mode: standalone)').matches ||
  window.navigator.standalone === true;

const refreshButton = () => {
  if (installButton) {
    installButton.hidden = isStandalone();
  }
};

refreshButton();

window.addEventListener('beforeinstallprompt', event => {
  event.preventDefault();
  installPrompt = event;
  refreshButton();
});

window.addEventListener('appinstalled', () => {
  installPrompt = null;

  if (installButton) {
    installButton.hidden = true;
  }

  if (installHelp) {
    installHelp.hidden = true;
  }
});

if (installButton) {
  installButton.addEventListener('click', async () => {
    if (installPrompt) {
      try {
        await installPrompt.prompt();
        await installPrompt.userChoice;
      } catch (_) {
      }

      installPrompt = null;
      return;
    }

    if (!installHelp) {
      return;
    }

    const isIOS =
      /iPad|iPhone|iPod/.test(navigator.userAgent) ||
      (
        navigator.platform === 'MacIntel' &&
        navigator.maxTouchPoints > 1
      );

    installHelp.textContent = isIOS
      ? 'No Safari: toque em Compartilhar → Adicionar à Tela de Início. Se aparecer, ative Abrir como App da Web e toque em Adicionar.'
      : 'No Chrome: abra o menu ⋮ e escolha Instalar aplicativo ou Adicionar à tela inicial. Se não aparecer, aguarde alguns segundos e atualize a página.';

    installHelp.hidden = !installHelp.hidden;
  });
}

if (
  'serviceWorker' in navigator &&
  window.isSecureContext
) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register(
      '/sw.js',
      { scope: '/' }
    ).catch(() => {});
  });
}
"""


def install_pwa(app):
    @app.get("/manifest.webmanifest")
    def pwa_manifest():
        manifest = {
            "id": "/",
            "name": "Reversa e Lixo Eletrônico",
            "short_name": "Reversa",
            "lang": "pt-BR",
            "start_url": "/",
            "scope": "/",
            "display": "standalone",
            "background_color": "#102d40",
            "theme_color": "#102d40",
            "icons": [
                {
                    "src": f"/app-icon/{size}.png",
                    "sizes": f"{size}x{size}",
                    "type": "image/png",
                    "purpose": "any maskable",
                }
                for size in (192, 512)
            ],
        }

        return Response(
            json.dumps(
                manifest,
                ensure_ascii=False,
            ),
            content_type=(
                "application/manifest+json; charset=utf-8"
            ),
        )

    @app.get("/app-icon/<int:size>.png")
    def pwa_icon(size):
        if size not in (180, 192, 512):
            abort(404)

        return Response(
            app_icon(size),
            mimetype="image/png",
        )

    @app.get("/offline.html")
    def pwa_offline():
        return Response(
            OFFLINE,
            content_type="text/html; charset=utf-8",
        )

    @app.get("/sw.js")
    def pwa_worker():
        return Response(
            WORKER,
            content_type=(
                "application/javascript; charset=utf-8"
            ),
            headers={
                "Service-Worker-Allowed": "/",
                "Cache-Control": "no-cache",
            },
        )

    @app.get("/pwa.js")
    def pwa_script():
        return Response(
            SCRIPT,
            content_type=(
                "application/javascript; charset=utf-8"
            ),
        )

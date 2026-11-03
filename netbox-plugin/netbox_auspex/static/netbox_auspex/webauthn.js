/* Clés de sécurité (WebAuthn) : inscription et connexion.
 *
 * Les options (défi, domaine, clés acceptées) sont fournies par le serveur
 * dans <script type="application/json" id="webauthn-options">. Le bouton
 * [data-webauthn="create"|"get"] appelle la clé, puis la réponse est postée
 * dans le champ « credential » du formulaire englobant. Aucune donnée n'est
 * interprétée comme du HTML.
 */
(function () {
  "use strict";

  function b64urlToBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function bufToB64url(buf) {
    var bytes = new Uint8Array(buf), bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function options() {
    var el = document.getElementById("webauthn-options");
    return el ? JSON.parse(el.textContent) : null;
  }

  function showError(text) {
    var el = document.getElementById("webauthn-error");
    if (el) { el.textContent = text; el.hidden = false; }
  }

  function message(err) {
    if (!err) return "La clé n'a pas répondu.";
    if (err.name === "NotAllowedError") return "Opération annulée ou délai dépassé : réessayer.";
    if (err.name === "InvalidStateError") return "Cette clé est déjà inscrite pour ce compte.";
    if (err.name === "SecurityError") return "Adresse de la page non autorisée pour les clés de sécurité.";
    if (err.name === "NotSupportedError") return "Cette clé ne prend en charge aucun algorithme accepté.";
    return "La clé n'a pas pu répondre (" + err.name + ").";
  }

  function run(button) {
    var opts = options();
    if (!opts) return;
    if (!window.PublicKeyCredential || !navigator.credentials) {
      showError("Ce navigateur ne prend pas en charge les clés de sécurité.");
      return;
    }
    var mode = button.getAttribute("data-webauthn");
    var publicKey = Object.assign({}, opts, { challenge: b64urlToBuf(opts.challenge) });
    var call;
    if (mode === "create") {
      publicKey.user = Object.assign({}, opts.user, { id: b64urlToBuf(opts.user.id) });
      publicKey.excludeCredentials = (opts.excludeCredentials || []).map(function (c) {
        return { type: c.type, id: b64urlToBuf(c.id) };
      });
      call = navigator.credentials.create({ publicKey: publicKey });
    } else {
      publicKey.allowCredentials = (opts.allowCredentials || []).map(function (c) {
        return { type: c.type, id: b64urlToBuf(c.id) };
      });
      call = navigator.credentials.get({ publicKey: publicKey });
    }
    button.disabled = true;
    call.then(function (cred) {
      var r = cred.response, response = { clientDataJSON: bufToB64url(r.clientDataJSON) };
      if (mode === "create") {
        response.attestationObject = bufToB64url(r.attestationObject);
      } else {
        response.authenticatorData = bufToB64url(r.authenticatorData);
        response.signature = bufToB64url(r.signature);
      }
      var form = button.closest("form");
      form.querySelector("input[name=credential]").value = JSON.stringify({
        id: bufToB64url(cred.rawId), type: cred.type, response: response
      });
      form.submit();
    }).catch(function (err) {
      button.disabled = false;
      showError(message(err));
    });
  }

  document.addEventListener("click", function (ev) {
    var button = ev.target.closest("[data-webauthn]");
    if (button) { ev.preventDefault(); run(button); }
  });
})();

// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

var KAPA_ATTRS = {
  src: "https://widget.kapa.ai/kapa-widget.bundle.js",
  "data-website-id": "91d6cd50-0276-4125-b8c1-3fe897e8fe47",
  "data-project-name": "Seal Knowledge",
  "data-project-color": "#92a4ff",
  "data-button-hide": "true",
  "data-modal-title": "Ask Seal AI",
  "data-modal-ask-ai-input-placeholder": "Ask me anything about Seal!",
  "data-modal-example-questions":
    "How do I encrypt data with Seal?,What is threshold encryption?,How do I create an access policy?,What are key servers?",
  "data-modal-body-bg-color": "#E0E2E6",
  "data-source-link-bg-color": "#FFFFFF",
  "data-source-link-border": "#92a4ff",
  "data-answer-feedback-button-bg-color": "#FFFFFF",
  "data-answer-copy-button-bg-color": "#FFFFFF",
  "data-thread-clear-button-bg-color": "#FFFFFF",
  "data-modal-image": "/img/logo.svg",
  "data-mcp-enabled": "true",
  "data-mcp-server-url": "https://sui.mcp.kapa.ai",
  "data-mcp-button-text": "Use Seal MCP Server",
};

function ensureKapaScript() {
  if (document.getElementById("__kapa_script")) return;
  var s = document.createElement("script");
  s.id = "__kapa_script";
  s.async = true;
  for (var key in KAPA_ATTRS) {
    s.setAttribute(key, KAPA_ATTRS[key]);
  }
  document.head.appendChild(s);
}

function injectKapaButton() {
  if (document.getElementById("__kapa_navbar_btn")) return;

  var rightItems =
    document.querySelector(".navbar__items--right") ||
    document.querySelector(".navbar__items:last-child");
  if (!rightItems) return;

  var btn = document.createElement("button");
  btn.id = "__kapa_navbar_btn";
  btn.type = "button";
  btn.className = "kapa-trigger-btn";
  btn.innerHTML =
    '<img src="/img/logo.svg" alt="" width="23" height="23" />' +
    '<span class="kapa-label">Ask Seal AI</span>';
  btn.addEventListener("click", function () {
    if (typeof window !== "undefined" && window.Kapa) {
      window.Kapa.open();
    }
  });

  rightItems.appendChild(btn);
}

export function onRouteDidUpdate() {
  ensureKapaScript();
  var tries = [0, 100, 300];
  tries.forEach(function (t) {
    setTimeout(injectKapaButton, t);
  });
}

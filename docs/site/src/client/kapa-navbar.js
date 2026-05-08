// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

function getBaseUrl() {
  const meta = document.querySelector('meta[name="docusaurus_baseUrl"]');
  return (meta && meta.content) || "/";
}

function injectKapaButton() {
  if (document.getElementById("__kapa_navbar_btn")) return;

  const rightItems =
    document.querySelector(".navbar__items--right") ||
    document.querySelector(".navbar__items:last-child");
  if (!rightItems) return;

  const baseUrl = getBaseUrl();
  const btn = document.createElement("button");
  btn.id = "__kapa_navbar_btn";
  btn.type = "button";
  btn.className = "kapa-trigger-btn";
  btn.innerHTML =
    '<img src="' + baseUrl + 'img/logo.svg" alt="" width="23" height="23" />' +
    '<span class="kapa-label">Ask Seal AI</span>';
  btn.addEventListener("click", () => {
    if (typeof window !== "undefined" && window.Kapa) {
      window.Kapa.open();
    }
  });

  rightItems.appendChild(btn);
}

export function onRouteDidUpdate() {
  const tries = [0, 100, 300];
  tries.forEach((t) => setTimeout(injectKapaButton, t));
}

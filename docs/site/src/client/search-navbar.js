// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

function injectSearchButton() {
  if (document.getElementById("__search_navbar_btn")) return;

  var rightItems =
    document.querySelector(".navbar__items--right") ||
    document.querySelector(".navbar__items:last-child");
  if (!rightItems) return;

  var btn = document.createElement("button");
  btn.id = "__search_navbar_btn";
  btn.type = "button";
  btn.className = "DocSearch DocSearch-Button";
  btn.style.cssText =
    "display:inline-flex;align-items:center;cursor:pointer;flex-shrink:0;";
  btn.innerHTML =
    '<span class="DocSearch-Button-Container" style="display:flex;align-items:center">' +
    '<svg width="20" height="20" class="DocSearch-Search-Icon" viewBox="0 0 20 20" aria-hidden="true">' +
    '<path d="M14.386 14.386l4.0877 4.0877-4.0877-4.0877c-2.9418 2.9419-7.7115 2.9419-10.6533 0-2.9418-2.9418-2.9419-7.7115 0-10.6533 2.9418-2.9419 7.7115-2.9419 10.6533 0 2.9419 2.9418 2.9419 7.7115 0 10.6533z" stroke="currentColor" fill="none" fill-rule="evenodd" stroke-linecap="round" stroke-linejoin="round"/>' +
    "</svg>" +
    '<span class="DocSearch-Button-Placeholder" style="font-weight:600">Search</span>' +
    "</span>";

  btn.addEventListener("click", function () {
    document.dispatchEvent(new CustomEvent("open-search-modal"));
  });

  // Insert before the kapa button if it exists, otherwise append
  var kapaBtn = document.getElementById("__kapa_navbar_btn");
  if (kapaBtn) {
    rightItems.insertBefore(btn, kapaBtn);
  } else {
    rightItems.appendChild(btn);
  }
}

export function onRouteDidUpdate() {
  var tries = [0, 100, 300];
  tries.forEach(function (t) {
    setTimeout(injectSearchButton, t);
  });
}

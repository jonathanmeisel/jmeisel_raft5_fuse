import { mount } from "svelte";
import App from "./App.svelte";
import "./app.css";

// Refuse to run inside a frame: another site could frame the app and trick
// a user into clicking Share or Revoke. A <meta> CSP can't say
// frame-ancestors, and GitHub Pages can't send the header.
if (window.top !== window.self) {
  document.body.textContent = "raft5fs doesn't run inside a frame.";
} else {
  mount(App, { target: document.getElementById("app") });
}

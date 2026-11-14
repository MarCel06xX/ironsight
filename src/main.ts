// Phase 0 placeholder: the real UI is built from phase 1 on.
const app = document.querySelector<HTMLDivElement>("#app");
if (app) {
  const heading = document.createElement("h1");
  heading.textContent = "Ironsight";
  app.append(heading);
}

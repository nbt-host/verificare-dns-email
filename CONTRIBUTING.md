# Contributing

Thanks for helping. This is a small, dependency-free project, and we would like to keep it that way.

- **Bugs:** open an issue with the domain you checked (or a made-up one that reproduces the problem), what the tool said and what you expected.
- **Fixes and features:** open a pull request. Keep it to plain HTML, CSS and vanilla JavaScript: no frameworks, no build step, no third-party scripts, no tracking.
- **Both languages:** `assets/instrumente.js` (Romanian) and `assets/instrumente.en.js` (English) share the same logic. A change to the logic goes into both files; a new message needs both a Romanian and an English text.
- **Privacy:** nothing may leave the browser except the DNS name being looked up, and only to a public DNS-over-HTTPS resolver.
- **Test before sending:** run `python3 -m http.server 8000`, check a few real domains in both languages and look at the pages at 320 px wide (no horizontal scroll).

Contributions are released under the MIT licence of the project.

---

**Pe scurt, în română:** issue-urile și pull request-urile sunt binevenite. Fără biblioteci, fără pas de build, fără scripturi externe; orice schimbare de logică intră în ambele fișiere JS (RO și EN). Ne poți scrie și la suport@nbt-host.com.

# WereldExplorer

Deze versie gebruikt **Wikidata** als databron (geen custom API) en voegt echte **accounts + sessies (cookies)** toe met een **SQLite database**.

## Starten (lokaal)

1. Installeer dependencies

```bash
cd wereldexplorer
npm install
```

2. Start de server

```bash
npm start
```

3. Open de app

- Home: `http://localhost:3000/`
- App: `http://localhost:3000/app.html`

## Wat is aangepast

- **Homepagina**: modernere layout/typografie/spacing en duidelijke CTA's.
- **Navigatie**: op de app-pagina een **Home** knop.
- **API**: custom API verwijderd; ophalen gebeurt rechtstreeks via **Wikidata SPARQL**.
- **Land → uitklappen**: bij een land verschijnt de knop **Galerij**; dit opent een full-screen foto-galerij.
- **Authenticatie**: login + registreren met validatie, fouten, en nette UX.
- **Sessies**: HttpOnly cookie (`we_session`) en server-side sessies in de DB.
- **Database**: SQLite met `users` en `sessions`; wachtwoorden worden gehasht.
- **Toegangsbeperking**: zonder login zijn plekken/bezienswaardigheden niet zichtbaar.

## Config (optioneel)

- `PORT` (default 3000)
- `DB_FILE` (default `./data/app.db`)
- `SESSION_DAYS` (default 7)


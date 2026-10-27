# Aegis Security Dashboard

React + TypeScript frontend connected to the Cyber Risk FastAPI backend. Repository scans read source files from GitHub archives and return the backend report.

## Run locally

Requirements: Node.js 20+, npm, and Python 3.10+.

Start the backend in one terminal:

```bash
cd cyber-risk--app/backend
python -m pip install -r requirements.txt
python src/main.py
```

Start the frontend in another terminal:

```bash
cd aegis-demo
npm install
npm run dev
```

Visit the URL displayed by Vite (usually `http://localhost:5173`). The Vite development proxy forwards `/scan` requests to `http://localhost:8000`.

After the demo login, enter a GitHub repository as `owner/repository` or a `github.com` URL and provide a GitHub access token with read access to that repository. The backend checks that the authenticated GitHub account is the repository owner before downloading the archive. Collaborators who do not own the repository are rejected. The token is sent in the request header and is not saved with scan history.

The initial email/password login is demo-only; it does not authenticate a GitHub account. Repository ownership is verified separately using the token entered on the setup screen.

To test a production build:

```bash
npm run build
npm run preview
```

Analyses and login status are stored in your browser's `localStorage`. A failed backend request is shown as an error; it does not create a sample scan report.


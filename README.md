# Cyber Risk App

Educational project for the GenWorks Open Agent Hackathon.

This app inspects a website or an uploaded source archive and reports defensive findings. It matches known CVEs to exact package versions and can download that report as JSON or PDF. It does not run exploits, and it does not attack live systems.

## Disclaimer and limitation of liability

This software is a hackathon demo made for education and learning. It is not a commercial product, not a security certification, and not legal, security, or professional advice.

Use it only on systems you own or have explicit permission to test. You are responsible for every scan you start, including the target, the data you upload, and what you do with the report.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. THE AUTHORS, CONTRIBUTORS, AND ANYONE WHO DISTRIBUTES THIS REPOSITORY DISCLAIM ALL LIABILITY FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT, OR OTHERWISE, ARISING FROM OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE, TO THE MAXIMUM EXTENT PERMITTED BY LAW.

You assume the entire risk of using this repository. If you do not accept that, do not use, copy, or run it.

## What a scan does

- A URL scan is allowed only after the site serves an issued token at `/.well-known/cyber-risk-verify.txt`. Private, loopback, and link-local hosts are refused.
- A source scan reads owner labels in the upload. If a labeled owner does not match the caller, the scan is refused. If the source has no owner label, the scan continues and treats the code as the caller's.
- Checks stay inspect-only. Stay-inspect mode is off unless the request sets both `stay_inspect` and `override_command`.

## Run the API

```bash
pip install -r backend/requirements.txt
python backend/src/main.py
```

The API listens on `127.0.0.1:8000`. Copy `.env.example` to `.env` only if you want optional Zetaris or model settings. The app still runs without those values.

Useful routes: `/health`, `/tools`, `/cves`, `/verify/url`, `/verify/source`, `/scan/url`, `/scan/source`, and `/report/pdf`.

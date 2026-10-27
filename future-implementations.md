# Future implementations

These two items are written down so they are not lost. They are not part of the current scan behavior.

## 2. Confirm the target before scanning it

The API still fetches any http or https URL the caller sends, and it follows redirects.

Later work:

- Ask the user to confirm they are allowed to scan that target before the GET runs.
- Refuse loopback, private, and link-local addresses.
- Refuse a redirect that lands on one of those addresses.
- Keep a size cap on uploaded archives, including the total unzipped size and the number of files.

Until that exists, run the API on localhost and only point it at sites you own.

## 6. Stay inspect-only

The product inspects a response or uploaded source and matches known vulnerabilities to installed versions. It does not send attack traffic, and it does not run exploit code.

If a safe environment is added later, it should run inspection and dependency checks only. It should not execute exploit kits or “test the app against a zero-day” by attacking it. Historical CVE notes in the knowledge folder stay case studies for remediation text.

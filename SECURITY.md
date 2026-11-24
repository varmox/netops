# Security policy

NetOps is security software that holds credentials for your network. Please report vulnerabilities
privately.

## Reporting

Use GitHub's private vulnerability reporting ("Report a vulnerability" in the Security tab of this
repository). Please include the version (image digest or commit), steps to reproduce, and impact.

You can expect an acknowledgement within 7 days and a fix or mitigation plan within 30 days for
confirmed issues. Credit is given in the release notes unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes. Installations update themselves on a schedule
(signed images, see [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md)).

## Scope

In scope: the backend, the web UI, the container images, the host playbook, the update chain.
Out of scope: vulnerabilities in devices NetOps manages (report those to their vendors), and attacks that
require the vault passphrase or root on the host.

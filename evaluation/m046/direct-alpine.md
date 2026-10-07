# Finite direct Alpine feasibility

This S01 experiment imports the seven pinned direct-inventory/schema wheels and
performs one small CycloneDX 1.6 export on both native architectures. It uses a
source-free overlay on the exact released v1.7.38 scanner image and preserves
its compressed baseline layers and image defaults. Trusted wheel preparation
may download public pinned artifacts; installation inside the image build is
offline, hash-verified and isolated in a venv without pip.

The synthetic source contains pip 26.0.1 in two independent roots. The controller
checks both exported source occurrences and their source hashes. It inspects
the actual immutable image, user, command, mount and Docker enforcement settings
before starting the probe: no network, read-only root/source, no capabilities,
no privilege escalation, 2 CPU, 2 GiB with no swap and 32 PIDs. The probe has its
own 25-second alarm and the host uses a 35-second deadline. A separate-session
watchdog owns cleanup before create/start, observes a parent-liveness pipe and
enforces an independent 90-second lifecycle deadline. Parent success requires
a cleanup receipt bound to the unique name and full container ID. Controller
death triggers 30 seconds of cleanup polling; those abnormal attempts never
qualify as success, and Docker-daemon uncertainty stays explicit. CLI children
have a kernel parent-death signal and do not inherit the liveness pipe.
This is a small feasibility observation, not an aggregate resource experiment.

All installed wheel Python/native code hashes, including bundled `.so.1`
libraries, must match prepared wheel bytes. `/proc/self/maps` proves the rpds
extension and bundled libgcc were loaded with those identities on this exercised
path. It does not establish every lazy native dependency or distribution
compliance. The bounded OCI verifier checks every layer digest/diff ID, exact
released base prefix/configuration, and actual added compressed layer bytes.
The proposed 250 MiB ceiling remains subject to architecture budget review.

The two musl rpds hashes were independently checked against their exact PyPI
publication subjects and GitHub OIDC publisher workflow. They add CP314 native
Alpine feasibility; they do not silently change any production scanner route,
generic resource-image override or declared language support.

Vendor libgcc origin, notices/source obligations and final native distribution
closure remain specific S06 work. No incompatible license has been established;
this experiment does not claim release compliance, complete matching, engine
selection, trace qualification, production deployment or milestone closure.

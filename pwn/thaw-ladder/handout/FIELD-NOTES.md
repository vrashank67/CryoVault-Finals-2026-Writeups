# thawd 7.3 - field notes, pod 7

Pod 7 runs the 7.3 field build of the controller. FROSTLANG.md and frostbench.py are the
7.2 bench. The two builds are not the same, and this kit does not document the field
build: where the pod and the bench disagree, the pod is right.

Known about pod 7:

- **BOOT.** The revision word reads `0x0703`.
- **Sessions.** Every connection is a fresh controller process with a fresh session.
  Everything a session uses is drawn when it opens and is gone when it closes.
- **Field limits.** See README.md.

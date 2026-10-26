# THAW LADDER - pod 7

Pod 7 went into vitrification with the rest of bay C. Its controller still runs. Wake the
pod.

## Your controller

Your team has its own field controller: `nc <host> <port>`. Every connection is a fresh
controller process with a fresh session; when you disconnect, that session is gone.

Field limits, per session: 40 command lines per second with a burst of 40 (lines beyond
that are not dropped, they wait their turn, so you may send many lines before reading any
answers); 16384 plans; 3600 seconds; 60 seconds without a complete line ends the session
(`BYE idle`). A controller holds 48 sessions; a new connection to a full controller ends the
session that has been quiet longest (`BYE evicted`).

## The kit

| File | What |
|---|---|
| `FROSTLANG.md` | the programmer's manual for thaw plans and the protocol, as of the 7.2 bench |
| `frostbench.py` | the 7.2 bench controller (Python 3, standard library only) |
| `FIELD-NOTES.md` | what is known about pod 7's 7.3 field build |
| `seccomp.policy` | the sandbox filter every field session process runs under |

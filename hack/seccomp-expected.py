"""Compute expected seccomp verdicts for amicontained probes from a moby-format profile,
and diff them against amicontained -json output.
usage: seccomp-expected.py PROFILE.json TABLE.go CAPS(comma) REPORT.json
The architecture (amd64 or arm64) is taken from the table's file name."""
import json, os, re, sys

ERRNO = {1: "EPERM", 13: "EACCES", 38: "ENOSYS"}
CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWNET, SIGCHLD = 0x10000000, 0x20000, 0x40000000, 17
ARG_PROBES = {
    "clone(SIGCHLD) - create a process": ("clone", [SIGCHLD]),
    "clone(CLONE_NEWUSER) - create a user namespace": ("clone", [CLONE_NEWUSER | SIGCHLD]),
    "clone(CLONE_NEWNS) - create a mount namespace": ("clone", [CLONE_NEWNS | SIGCHLD]),
    "unshare(CLONE_NEWUSER) - create a user namespace": ("unshare", [CLONE_NEWUSER]),
    "unshare(CLONE_NEWNS) - create a mount namespace": ("unshare", [CLONE_NEWNS]),
    "unshare(CLONE_NEWNET) - create a network namespace": ("unshare", [CLONE_NEWNET]),
    "personality(PER_LINUX)": ("personality", [0]),
    "personality(ADDR_NO_RANDOMIZE) - disable ASLR": ("personality", [0x0040000]),
    "socket(AF_VSOCK) - host/guest vsock": ("socket", [40, 1]),
    "ioctl(TIOCSTI) - inject terminal input": ("ioctl", [0, 0x5412]),
}

def load(profile, caps):
    rules = {}
    for r in profile["syscalls"]:
        inc, exc = r.get("includes", {}), r.get("excludes", {})
        if inc.get("caps") and not set(inc["caps"]) <= caps: continue
        if exc.get("caps") and set(exc["caps"]) & caps: continue
        if inc.get("arches") and ARCH not in inc["arches"]: continue
        if exc.get("arches") and ARCH in exc["arches"]: continue
        for n in r["names"]:
            rules.setdefault(n, []).append(r)
    return rules

def cond_ok(c, args):
    v = args[c["index"]] if c["index"] < len(args) else 0
    op, val = c["op"], c["value"]
    return {"SCMP_CMP_EQ": v == val, "SCMP_CMP_NE": v != val, "SCMP_CMP_LT": v < val,
            "SCMP_CMP_LE": v <= val, "SCMP_CMP_GT": v > val, "SCMP_CMP_GE": v >= val,
            "SCMP_CMP_MASKED_EQ": (v & val) == c.get("valueTwo", 0)}[op]

def verdict(profile, rules, name, args):
    for r in rules.get(name, []):
        if all(cond_ok(c, args) for c in r.get("args") or []):
            if r["action"] == "SCMP_ACT_ALLOW": return "allow"
            if r["action"] == "SCMP_ACT_ERRNO":
                return ERRNO.get(r.get("errnoRet", profile.get("defaultErrnoRet", 1)), str(r.get("errnoRet")))
    if profile["defaultAction"] == "SCMP_ACT_ALLOW": return "allow"
    return ERRNO.get(profile.get("defaultErrnoRet", 1))

ARCH = "arm64" if "arm64" in os.path.basename(sys.argv[2]) else "amd64"
profile = json.load(open(sys.argv[1]))
table = re.findall(r'\{(\d+), "(\w+)"\}', open(sys.argv[2]).read())
caps = {"CAP_" + c.strip().upper() for c in sys.argv[3].split(",") if c.strip()}
report = json.load(open(sys.argv[4]))["seccomp"]
rules = load(profile, caps)

got = {s["syscall"]: (s["errno"] if s["action"] == "errno" else s["action"]) for s in report.get("syscalls", [])}
exp = {name: verdict(profile, rules, name, []) for _, name in table}
mism = [(n, exp[n], got.get(n)) for _, n in table if exp[n] != got.get(n)]
exp_blocked = sum(1 for v in exp.values() if v != "allow")
got_blocked = sum(1 for v in got.values() if v != "allow")
print(f"syscalls: expected blocked={exp_blocked} reported blocked={got_blocked} mismatches={len(mism)}")
for n, e, g in mism: print(f"   MISMATCH {n}: expected {e}, got {g}")
gota = {a["args"]: (a["errno"] if a["action"] == "errno" else a["action"]) for a in report.get("argument_checks", [])}
for desc, (name, args) in ARG_PROBES.items():
    e = verdict(profile, rules, name, args)
    flag = "ok " if e == gota.get(desc) else "MISMATCH"
    print(f"   {flag} {desc}: expected {e}, got {gota.get(desc)}")

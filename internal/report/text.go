package report

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/genuinetools/amicontained/internal/lsm"
	"github.com/genuinetools/amicontained/internal/procfs"
	"github.com/genuinetools/amicontained/internal/seccomp"
	"github.com/genuinetools/amicontained/internal/sockets"
)

// TextOptions controls WriteText.
type TextOptions struct {
	Color   bool
	Verbose bool // full lists instead of summaries
}

const (
	labelWidth = 14
	lineWidth  = 80
)

type printer struct {
	w io.Writer
	TextOptions
}

func (p *printer) style(code, s string) string {
	if !p.Color || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p *printer) bold(s string) string   { return p.style("1", s) }
func (p *printer) red(s string) string    { return p.style("1;31", s) }
func (p *printer) yellow(s string) string { return p.style("33", s) }
func (p *printer) cyan(s string) string   { return p.style("36", s) }
func (p *printer) dim(s string) string    { return p.style("2", s) }

func (p *printer) section(title string) {
	fmt.Fprintf(p.w, "\n%s\n", p.bold(title))
}

// field prints "  label  value", wrapping long values under the value column.
func (p *printer) field(label, value string) {
	if len(label) >= labelWidth {
		fmt.Fprintf(p.w, "  %s\n", label)
		label = ""
	}
	fmt.Fprintf(p.w, "  %-*s%s\n", labelWidth, label, value)
}

// list prints words wrapped to the line width, starting in the value column.
func (p *printer) list(label string, words []string) {
	if len(words) == 0 {
		p.field(label, "none")
		return
	}
	indent := 2 + labelWidth
	var lines []string
	line := ""
	for _, word := range words {
		if line != "" && indent+len(line)+1+len(word) > lineWidth {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	lines = append(lines, line)
	p.field(label, lines[0])
	for _, l := range lines[1:] {
		p.field("", l)
	}
}

// wrap splits s into lines of at most width runes, breaking at spaces.
func wrap(s string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		if line != "" && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// WriteText renders the report for a terminal.
func (r *Report) WriteText(w io.Writer, opts TextOptions) {
	p := &printer{w: w, TextOptions: opts}
	p.header(r)
	p.findings(r.Findings)
	p.runtime(r)
	p.isolation(r)
	p.privileges(r)
	p.securityModules(r.LSM)
	p.sockets(r.Sockets)
	p.seccomp(r.Seccomp, r.Runtime.Sandbox)
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func (p *printer) header(r *Report) {
	what := "no container detected"
	if rt := r.Runtime; rt != nil && rt.Engine != "" {
		what = rt.Engine + " container"
		if rt.Engine == "unknown" {
			what = "container (engine unknown)"
		}
		if rt.ContainerID != "" {
			what += " " + shortID(rt.ContainerID)
		}
		if rt.Orchestrator != "" {
			what += " in " + rt.Orchestrator
		}
		if rt.Sandbox != "" {
			what += ", " + rt.Sandbox + " sandbox"
		}
	}
	fmt.Fprintf(p.w, "%s %s - %s\n", p.bold("amicontained"), r.Version, what)
}

func (p *printer) findings(fs []Finding) {
	p.section("FINDINGS")
	if len(fs) == 0 {
		fmt.Fprintln(p.w, "  none: this looks like a default, isolated container")
		return
	}
	for _, f := range fs {
		var mark string
		switch f.Severity {
		case High:
			mark = p.red("!")
		case Medium:
			mark = p.yellow("*")
		default:
			mark = p.cyan("i")
		}
		summary := wrap(f.Summary, lineWidth-4)
		if len(summary) == 0 {
			summary = []string{""}
		}
		fmt.Fprintf(p.w, "  %s %s\n", mark, summary[0])
		for _, line := range summary[1:] {
			fmt.Fprintf(p.w, "    %s\n", line)
		}
		for _, line := range wrap(f.Detail, lineWidth-4) {
			fmt.Fprintf(p.w, "    %s\n", p.dim(line))
		}
	}
}

func (p *printer) runtime(r *Report) {
	rt := r.Runtime
	p.section("RUNTIME")
	switch rt.Engine {
	case "":
		p.field("engine", "none detected")
	default:
		p.field("engine", rt.Engine)
	}
	if rt.Orchestrator != "" {
		p.field("orchestrator", rt.Orchestrator)
	}
	if rt.Sandbox != "" {
		p.field("sandbox", rt.Sandbox)
	}
	if rt.ContainerID != "" {
		id := rt.ContainerID
		if !p.Verbose {
			id = shortID(id)
		}
		p.field("container id", id)
	}
	if rt.PodUID != "" {
		p.field("pod uid", rt.PodUID)
	}
	switch {
	case len(rt.Evidence) == 0:
	case p.Verbose:
		for i, e := range rt.Evidence {
			label := ""
			if i == 0 {
				label = "evidence"
			}
			p.field(label, e)
		}
	default:
		e := rt.Evidence[0]
		if n := len(rt.Evidence) - 1; n > 0 {
			e += p.dim(fmt.Sprintf(" (+%d more, -v)", n))
		}
		p.field("evidence", e)
	}
}

func (p *printer) isolation(r *Report) {
	p.section("ISOLATION")

	var private, host, unsupported, errs []string
	likely := false
	for _, ns := range r.Namespaces {
		name := ns.Type
		if !ns.Exact && ns.Error == "" && !ns.Unsupported {
			name += "?"
			likely = true
		}
		switch {
		case ns.Unsupported:
			unsupported = append(unsupported, ns.Type)
		case ns.Error != "":
			errs = append(errs, ns.Type+" ("+ns.Error+")")
		case ns.Host:
			host = append(host, name)
		default:
			private = append(private, name)
		}
	}
	p.field("namespaces", "private: "+orNone(private))
	p.field("", "host:    "+orNone(host))
	if len(unsupported) > 0 {
		p.field("", "absent:  "+strings.Join(unsupported, " ")+" (not supported by this kernel)")
	}
	if len(errs) > 0 {
		p.field("", "error:   "+strings.Join(errs, ", "))
	}
	if likely {
		p.field("", p.dim("? = inferred from inode allocation order on this kernel"))
	}
	if r.HostPIDVisible {
		p.field("", "host processes are visible (kthreadd is PID 2)")
	}
	for i, m := range r.UserMappings {
		label := ""
		if i == 0 {
			label = "uid map"
		}
		p.field(label, fmt.Sprintf("%d-%d -> host %d-%d", m.ContainerID, m.ContainerID+m.Range-1, m.HostID, m.HostID+m.Range-1))
	}

	h := r.Hardening
	pr := h.Privileged
	p.list("privileged", strings.Fields(fmt.Sprintf("%d/%d indicators (%s)", pr.Present, len(pr.Indicators), pr.Verdict)))
	for _, i := range pr.Indicators {
		if !i.Present && !p.Verbose {
			continue
		}
		v := "no"
		if i.Present {
			v = p.yellow("yes")
		}
		line := i.Name + ": " + v
		if i.Detail != "" && (i.Present || p.Verbose) {
			line += p.dim(" (" + i.Detail + ")")
		}
		p.field("", line)
	}

	rootfs := "read-write"
	if h.RootFSReadOnly {
		rootfs = "read-only"
	}
	p.field("rootfs", rootfs)

	c := h.Cgroup
	cg := fmt.Sprintf("%s; memory %s, cpu %s, pids %s", c.Version, formatMemory(c.MemoryMax), formatCPU(c.CPUMax), formatLimit(c.PIDsMax))
	p.field("cgroup", cg)
	if p.Verbose && c.Path != "" {
		p.field("", "path "+c.Path)
	}
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, " ")
}

func (p *printer) privileges(r *Report) {
	p.section("PRIVILEGES")
	c := r.Capabilities
	if c == nil {
		p.field("capabilities", "error: "+r.CapsError)
	} else {
		// Group identical sets so the common case prints one list.
		sets := []struct {
			name string
			set  procfs.CapSet
		}{
			{"effective", c.Effective}, {"permitted", c.Permitted}, {"inheritable", c.Inheritable},
			{"bounding", c.Bounding}, {"ambient", c.Ambient},
		}
		var empty []string
		done := make([]bool, len(sets))
		label := "capabilities"
		for i, s := range sets {
			if done[i] {
				continue
			}
			if len(s.set.Names) == 0 {
				empty = append(empty, s.name)
				continue
			}
			names := []string{s.name}
			for j := i + 1; j < len(sets); j++ {
				if !done[j] && slices.Equal(sets[j].set.Names, s.set.Names) {
					names = append(names, sets[j].name)
					done[j] = true
				}
			}
			head := fmt.Sprintf("%s (%d)", strings.Join(names, " = "), len(s.set.Names))
			if p.Verbose {
				head += p.dim(" hex " + s.set.Hex)
			}
			p.field(label, head)
			label = ""
			p.list("", s.set.Names)
		}
		if len(empty) > 0 {
			p.field(label, strings.Join(empty, " = ")+": none")
		}
	}
	if r.NoNewPrivs != nil {
		p.field("no_new_privs", strconv.FormatBool(*r.NoNewPrivs))
	}
}

func (p *printer) securityModules(l *lsm.Report) {
	p.section("SECURITY MODULES")
	source := l.Source
	if source == "inferred" {
		source = "inferred, may be incomplete"
	}
	p.field("active", strings.Join(l.Active, " ")+p.dim(" ("+source+")"))
	for _, x := range []struct {
		name  string
		label *lsm.Label
	}{{"apparmor", l.AppArmor}, {"selinux", l.SELinux}, {"smack", l.Smack}} {
		if x.label == nil {
			continue
		}
		v := x.label.Label
		switch {
		case !x.label.Confining && x.label.Note != "":
			v += p.yellow(" (not confining: " + x.label.Note + ")")
		case !x.label.Confining:
			v += p.yellow(" (not confining)")
		}
		p.field(x.name, v)
	}
	if l.Landlock.Available {
		p.field("landlock", fmt.Sprintf("available, ABI %d", l.Landlock.ABI))
	} else {
		p.field("landlock", "unavailable ("+l.Landlock.Error+")")
	}
}

func (p *printer) sockets(r *sockets.Report) {
	p.section("SOCKETS")
	if r.Mode == sockets.ModeNone {
		fmt.Fprintln(p.w, "  not checked (-sockets none)")
		return
	}
	others, shown := 0, 0
	for _, s := range r.Sockets {
		if !s.Interesting() && !p.Verbose {
			others++
			continue
		}
		shown++
		var v string
		switch {
		case s.API == "grpc" || s.API == "http":
			what := s.Product
			if what == "" {
				what = "unidentified"
			}
			v = s.API + " API (" + what + ")"
		case s.Accessible:
			v = strings.TrimSpace(s.Product + " " + s.Version)
			if s.Controls() {
				v += "  " + p.red("ACCESSIBLE")
			}
		default:
			if s.Guess != "" {
				v = s.Guess + "?, "
			}
			v += s.Error
		}
		fmt.Fprintf(p.w, "  %s  %s %s\n", s.Path, v, p.dim("["+s.Source+"]"))
	}
	if shown == 0 {
		fmt.Fprintln(p.w, "  none found")
	}
	if others > 0 {
		fmt.Fprintf(p.w, "  %s\n", p.dim(fmt.Sprintf("+%d other sockets with no container API (-v lists them)", others)))
	}
	if sc := r.Scan; sc != nil && (p.Verbose || sc.Truncated != "") {
		line := fmt.Sprintf("scan: %d entries in %s", sc.Entries, sc.Duration)
		if sc.Truncated != "" {
			line += ", incomplete: " + sc.Truncated
		}
		fmt.Fprintf(p.w, "  %s\n", p.dim(line))
	}
}

func (p *printer) seccomp(s *seccomp.Report, sandbox string) {
	title := "SECCOMP"
	mode := string(s.Mode)
	if s.Mode == seccomp.ModeFiltering {
		mode += fmt.Sprintf(", %d filter(s), method %s", s.Filters, s.Method)
	}
	fmt.Fprintf(p.w, "\n%s  %s\n", p.bold(title), mode)
	if sandbox != "" {
		p.field("note", "this is the "+sandbox+" sandbox's seccomp state, not the host's")
	}
	for _, w := range s.Warnings {
		p.field("note", w)
	}
	if s.DefaultAction != nil {
		p.field("default", "unknown syscalls: "+describeAction(*s.DefaultAction))
	}
	if s.Method == seccomp.MethodNone || s.Mode != seccomp.ModeFiltering {
		return
	}

	blocked := s.Blocked()
	p.field("blocked", strconv.Itoa(len(blocked))+" syscalls")
	var groups []string
	byGroup := map[string][]string{}
	for _, b := range blocked {
		g := b.Errno
		if b.Action != seccomp.ActionErrno {
			g = string(b.Action)
		}
		if _, ok := byGroup[g]; !ok {
			groups = append(groups, g)
		}
		byGroup[g] = append(byGroup[g], b.Syscall)
	}
	for _, g := range groups {
		p.list("  "+g+" ("+strconv.Itoa(len(byGroup[g]))+")", byGroup[g])
	}

	width := 0
	for _, a := range s.ArgumentChecks {
		call, _, _ := strings.Cut(a.Args, " - ")
		width = max(width, len(call))
	}
	for i, a := range s.ArgumentChecks {
		label := ""
		if i == 0 {
			label = "arguments"
		}
		call, desc, _ := strings.Cut(a.Args, " - ")
		v := describeAction(a)
		if a.Blocked() {
			v = p.dim(v)
		}
		line := fmt.Sprintf("%-*s  %s", width, call, v)
		if desc != "" && p.Verbose {
			line += p.dim(" (" + desc + ")")
		}
		p.field(label, line)
	}

	var other []string
	for _, r := range s.Syscalls {
		if r.Action == seccomp.ActionUnknown || r.Action == seccomp.ActionSkipped {
			other = append(other, r.Syscall+"("+string(r.Action)+")")
		}
	}
	if len(other) > 0 {
		p.list("undetermined", other)
	}

	if p.Verbose {
		var allowed []string
		for _, r := range s.Syscalls {
			if r.Action == seccomp.ActionAllow {
				allowed = append(allowed, r.Syscall)
			}
		}
		p.list("allowed ("+strconv.Itoa(len(allowed))+")", allowed)
	}
}

func describeAction(r seccomp.Result) string {
	switch r.Action {
	case seccomp.ActionAllow:
		return "allowed"
	case seccomp.ActionErrno:
		return "blocked (" + r.Errno + ")"
	case seccomp.ActionKill, seccomp.ActionTrap:
		return "blocked (" + string(r.Action) + ")"
	}
	if r.Detail != "" {
		return string(r.Action) + " (" + r.Detail + ")"
	}
	return string(r.Action)
}

func formatLimit(v string) string {
	switch v {
	case "":
		return "unknown"
	case "max":
		return "none"
	}
	return v
}

func formatMemory(v string) string {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return formatLimit(v)
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	f, u := float64(n), 0
	for f >= 1024 && u < len(units)-1 {
		f /= 1024
		u++
	}
	return formatFloat(f) + " " + units[u]
}

func formatCPU(v string) string {
	quota, period, ok := strings.Cut(v, " ")
	q, err1 := strconv.ParseFloat(quota, 64)
	pd, err2 := strconv.ParseFloat(period, 64)
	if !ok || err1 != nil || err2 != nil || pd == 0 {
		return formatLimit(quota)
	}
	return formatFloat(q/pd) + " CPUs"
}

// formatFloat keeps up to two decimals: 1.5, 11.69, 256.
func formatFloat(f float64) string {
	s := strconv.FormatFloat(f, 'f', 2, 64)
	return strings.TrimSuffix(strings.TrimRight(s, "0"), ".")
}

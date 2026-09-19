use anyhow::{Context, Result, bail};
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::collections::{HashMap, VecDeque};

// Max args that fit in the SysV register set, I'm too lazy to implement stack marshalling
const MAX_CALL_ARGS: usize = 6;
const CALL_STACK_GAP: u64 = 1024;
pub const SCRATCH_OFFSET: u64 = 512;
pub const SCRATCH_SIZE: u64 = 256;

pub enum Stop {
    Hit(Pid, u64),
    Exited,
    Interrupted,
}

struct Breakpoint {
    original_byte: u8,
    armed: bool,
}

#[derive(Debug, Default)]
struct Thread {
    running: bool,
    pending_signal: Option<Signal>,
    sigstop_sent: bool,
}

impl Thread {
    fn newly_seen() -> Self {
        Thread {
            running: false,
            pending_signal: None,
            sigstop_sent: true,
        }
    }
}

pub struct Inferior {
    pub pid: Pid,
    threads: HashMap<Pid, Thread>,
    breakpoints: HashMap<u64, Breakpoint>,
    pending_hits: VecDeque<(Pid, u64)>,
    current: Option<Pid>,
    current_bp: Option<u64>,
    load_base: u64,
    peak_threads: usize,
    pub exit_code: Option<i32>,
}

impl Inferior {
    pub fn new(pid: Pid) -> Self {
        Inferior {
            pid,
            threads: HashMap::new(),
            breakpoints: HashMap::new(),
            pending_hits: VecDeque::new(),
            current: None,
            current_bp: None,
            load_base: 0,
            peak_threads: 0,
            exit_code: None,
        }
    }

    pub fn wait_initial(&mut self) -> Result<()> {
        match waitpid(self.pid, None)? {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {}
            other => bail!("unexpected initial wait status: {:?}", other),
        }
        ptrace::setoptions(
            self.pid,
            ptrace::Options::PTRACE_O_EXITKILL | ptrace::Options::PTRACE_O_TRACECLONE,
        )?;
        self.threads.insert(self.pid, Thread::default());
        self.note_thread_count();
        Ok(())
    }

    pub fn resolve_load_base(&mut self, is_pie: bool) -> Result<u64> {
        if !is_pie {
            self.load_base = 0;
            return Ok(0);
        }
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", self.pid))?;
        let exe = std::fs::read_link(format!("/proc/{}/exe", self.pid))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        for line in maps.lines() {
            let path = line.split_whitespace().nth(5);
            if let (Some(exe), Some(path)) = (&exe, path)
                && path == exe
            {
                let base = line.split('-').next().unwrap();
                self.load_base = u64::from_str_radix(base, 16)?;
                return Ok(self.load_base);
            }
        }
        bail!("could not find load base in /proc/{}/maps", self.pid)
    }

    pub fn load_base(&self) -> u64 {
        self.load_base
    }

    pub fn is_alive(&self) -> bool {
        !self.threads.is_empty()
    }

    pub fn current_bp(&self) -> Option<u64> {
        self.current_bp
    }

    pub fn dump_regs(&self) -> Result<Vec<(&'static str, u64)>> {
        let r = ptrace::getregs(self.ptrace_pid())?;
        Ok(vec![
            ("rdi", r.rdi),
            ("rsi", r.rsi),
            ("rdx", r.rdx),
            ("rcx", r.rcx),
            ("r8", r.r8),
            ("r9", r.r9),
            ("rax", r.rax),
            ("rbx", r.rbx),
            ("r10", r.r10),
            ("r11", r.r11),
            ("r12", r.r12),
            ("r13", r.r13),
            ("r14", r.r14),
            ("r15", r.r15),
            ("rsp", r.rsp),
            ("rbp", r.rbp),
            ("rip", r.rip),
        ])
    }

    pub fn peak_threads(&self) -> usize {
        self.peak_threads
    }

    fn note_thread_count(&mut self) {
        self.peak_threads = self.peak_threads.max(self.threads.len());
    }

    pub fn set_breakpoint(&mut self, static_addr: u64, armed: bool) -> Result<u64> {
        let runtime = static_addr.wrapping_add(self.load_base);
        if self.breakpoints.contains_key(&runtime) {
            if armed {
                self.arm(runtime)?;
            }
            return Ok(runtime);
        }
        let tid = self.ptrace_pid();
        let word = ptrace::read(tid, runtime as *mut _)? as u64;
        let original_byte = (word & 0xff) as u8;
        self.breakpoints.insert(
            runtime,
            Breakpoint {
                original_byte,
                armed: false,
            },
        );
        if armed {
            self.arm(runtime)?;
        }
        Ok(runtime)
    }

    pub fn arm(&mut self, runtime_addr: u64) -> Result<()> {
        let Some(bp) = self.breakpoints.get(&runtime_addr) else {
            bail!("no breakpoint registered at {runtime_addr:#x}");
        };
        if bp.armed {
            return Ok(());
        }
        self.set_byte(runtime_addr, 0xcc)?;
        if let Some(bp) = self.breakpoints.get_mut(&runtime_addr) {
            bp.armed = true;
        }
        Ok(())
    }

    pub fn disarm(&mut self, runtime_addr: u64) -> Result<()> {
        let Some(bp) = self.breakpoints.get(&runtime_addr) else {
            bail!("no breakpoint registered at {runtime_addr:#x}");
        };
        if !bp.armed {
            return Ok(());
        }
        let orig = bp.original_byte;
        self.set_byte(runtime_addr, orig)?;
        if let Some(bp) = self.breakpoints.get_mut(&runtime_addr) {
            bp.armed = false;
        }
        Ok(())
    }

    pub fn run_to_breakpoint(&mut self) -> Result<Stop> {
        loop {
            if let Some((tid, addr)) = self.pending_hits.pop_front() {
                self.current = Some(tid);
                self.current_bp = Some(addr);
                return Ok(Stop::Hit(tid, addr));
            }
            if self.threads.is_empty() {
                return Ok(Stop::Exited);
            }
            self.resume_all()?;
            let status = match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL)) {
                Ok(s) => s,
                Err(Errno::EINTR) => return Ok(Stop::Interrupted),
                Err(e) => return Err(e).context("waitpid"),
            };
            if self.handle_status(status)? {
                return Ok(Stop::Exited);
            }
            if !self.pending_hits.is_empty() {
                self.stop_world()?;
            }
        }
    }

    fn wait_thread(&self, tid: Pid) -> Result<WaitStatus> {
        loop {
            match waitpid(tid, Some(WaitPidFlag::__WALL)) {
                Ok(s) => return Ok(s),
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(e).context("waitpid"),
            }
        }
    }

    fn wait_any(&self) -> Result<WaitStatus> {
        loop {
            match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL)) {
                Ok(s) => return Ok(s),
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(e).context("waitpid"),
            }
        }
    }

    pub fn call_function(&mut self, func: u64, args: &[u64]) -> Result<(u64, u64)> {
        if args.len() > MAX_CALL_ARGS {
            bail!("call_function supports at most {MAX_CALL_ARGS} integer args");
        }
        let tid = match self.current {
            Some(t) => t,
            None => bail!("call_function is only valid inside a hook callback"),
        };
        let trap = match self.current_bp {
            Some(a) => a,
            None => bail!("no armed breakpoint available as a return trap"),
        };

        if !self.is_alive() {
            bail!("target is gone");
        }
        if !self.threads.contains_key(&tid) {
            bail!("thread {tid} exited before the injected call");
        }
        let saved = ptrace::getregs(tid)?;
        let mut regs = saved;

        let mut sp = (saved.rsp - CALL_STACK_GAP) & !0xfu64;
        sp -= 8;
        ptrace::write(tid, sp as *mut _, trap as i64)?;
        let expected_rsp = sp + 8;

        for (i, a) in args.iter().enumerate() {
            match i {
                0 => regs.rdi = *a,
                1 => regs.rsi = *a,
                2 => regs.rdx = *a,
                3 => regs.rcx = *a,
                4 => regs.r8 = *a,
                5 => regs.r9 = *a,
                _ => unreachable!(),
            }
        }
        regs.rsp = sp;
        regs.rip = func;
        regs.rax = 0;
        ptrace::setregs(tid, regs)?;

        let trap_was_armed = self.breakpoints.get(&trap).is_some_and(|bp| bp.armed);
        if !trap_was_armed {
            self.arm(trap)?;
        }
        let disarmed = self.disarm_all_except(trap)?;
        let result = self.await_call_return(tid, trap, expected_rsp);

        let stopped = self.stop_world();
        self.rearm(&disarmed)?;
        if !trap_was_armed {
            self.disarm(trap)?;
        }

        ptrace::setregs(tid, saved)?;
        stopped?;
        result
    }

    fn await_call_return(&mut self, tid: Pid, trap: u64, expected_rsp: u64) -> Result<(u64, u64)> {
        if let Some(t) = self.threads.get_mut(&tid) {
            t.running = false;
        }
        loop {
            self.resume_all().context("resuming for injected call")?;
            let status = self.wait_any().context("waiting for injected call")?;
            match status {
                WaitStatus::Stopped(t, Signal::SIGTRAP) if t == tid => {
                    self.mark_stopped(tid);
                    let mut regs = ptrace::getregs(tid)?;
                    if regs.rip.wrapping_sub(1) == trap {
                        if regs.rsp == expected_rsp {
                            return Ok((regs.rax, regs.rdx));
                        }
                        regs.rip = trap;
                        ptrace::setregs(tid, regs)?;
                        self.step_thread_over(tid, trap)?;
                    }
                }
                other => {
                    if !matches!(
                        other,
                        WaitStatus::PtraceEvent(..) | WaitStatus::Stopped(_, Signal::SIGSTOP)
                    ) {
                        eprintln!("[launcher] (during injected call, tid {tid}) {other:?}");
                        if let WaitStatus::Stopped(t, sig) = other
                            && sig != Signal::SIGSTOP
                            && let (Ok(r), Ok(si)) = (ptrace::getregs(t), ptrace::getsiginfo(t))
                        {
                            let addr = unsafe { si.si_addr() } as u64;
                            eprintln!(
                                "[launcher]   {sig:?} at rip={:#x} (base-relative {:#x}) fault addr={addr:#x} rsp={:#x}",
                                r.rip,
                                r.rip.wrapping_sub(self.load_base),
                                r.rsp
                            );
                        }
                    }
                    if self.handle_status(other)? {
                        bail!("target exited during an injected call");
                    }
                }
            }
        }
    }

    fn set_byte(&self, addr: u64, byte: u8) -> Result<()> {
        let tid = self.ptrace_pid();
        let word = ptrace::read(tid, addr as *mut _)? as u64;
        let patched = (word & !0xff) | byte as u64;
        ptrace::write(tid, addr as *mut _, patched as i64)?;
        Ok(())
    }

    fn disarm_all_except(&mut self, keep: u64) -> Result<Vec<u64>> {
        let addrs: Vec<u64> = self
            .breakpoints
            .iter()
            .filter(|(a, bp)| **a != keep && bp.armed)
            .map(|(a, _)| *a)
            .collect();
        for addr in &addrs {
            let orig = self.breakpoints[addr].original_byte;
            self.set_byte(*addr, orig)?;
        }
        Ok(addrs)
    }

    fn rearm(&mut self, addrs: &[u64]) -> Result<()> {
        for addr in addrs {
            self.set_byte(*addr, 0xcc)?;
        }
        Ok(())
    }

    pub fn step_over(&mut self, tid: Pid, runtime_addr: u64) -> Result<()> {
        self.current = None;
        self.current_bp = None;
        self.step_thread_over(tid, runtime_addr)
    }

    fn step_thread_over(&mut self, tid: Pid, runtime_addr: u64) -> Result<()> {
        let original_byte = match self.breakpoints.get(&runtime_addr) {
            Some(b) => b.original_byte,
            None => return Ok(()),
        };
        if !self.threads.contains_key(&tid) {
            return Ok(());
        }

        let word = ptrace::read(tid, runtime_addr as *mut _)? as u64;
        let restored = (word & !0xff) | original_byte as u64;
        ptrace::write(tid, runtime_addr as *mut _, restored as i64)?;

        let mut stepped = false;
        for _ in 0..64 {
            ptrace::step(tid, None)?;
            match self.wait_thread(tid)? {
                WaitStatus::Exited(t, code) => {
                    self.threads.remove(&t);
                    self.pending_hits.retain(|(p, _)| *p != t);
                    if t == self.pid {
                        self.exit_code = Some(code);
                    }
                    return Ok(());
                }
                WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                    stepped = true;
                    break;
                }
                WaitStatus::Stopped(_, Signal::SIGSTOP)
                    if self.threads.get(&tid).is_some_and(|t| t.sigstop_sent) =>
                {
                    if let Some(t) = self.threads.get_mut(&tid) {
                        t.sigstop_sent = false;
                    }
                }
                WaitStatus::Stopped(_, sig) => {
                    if let Some(t) = self.threads.get_mut(&tid) {
                        t.pending_signal = Some(sig);
                    }
                }
                WaitStatus::PtraceEvent(_, _, event) => {
                    if event == ptrace::Event::PTRACE_EVENT_CLONE as i32 {
                        let new = Pid::from_raw(ptrace::getevent(tid)? as i32);
                        self.threads.entry(new).or_insert_with(Thread::newly_seen);
                        self.note_thread_count();
                    }
                }
                other => bail!("unexpected status during step: {:?}", other),
            }
        }
        if !stepped {
            bail!(
                "thread {} would not step past breakpoint {:#x}",
                tid,
                runtime_addr
            );
        }

        if self
            .breakpoints
            .get(&runtime_addr)
            .is_some_and(|bp| bp.armed)
        {
            let word = ptrace::read(tid, runtime_addr as *mut _)? as u64;
            let patched = (word & !0xff) | 0xcc;
            ptrace::write(tid, runtime_addr as *mut _, patched as i64)?;
        }
        if let Some(t) = self.threads.get_mut(&tid) {
            t.running = false;
        }
        Ok(())
    }

    fn resume_all(&mut self) -> Result<()> {
        let tids: Vec<Pid> = self
            .threads
            .iter()
            .filter(|(_, t)| !t.running)
            .map(|(p, _)| *p)
            .collect();
        for tid in tids {
            if self.pending_hits.iter().any(|(p, _)| *p == tid) {
                continue;
            }
            let sig = match self.threads.get_mut(&tid) {
                Some(t) => t.pending_signal.take(),
                None => continue,
            };
            match ptrace::cont(tid, sig) {
                Ok(()) => {
                    if let Some(t) = self.threads.get_mut(&tid) {
                        t.running = true;
                    }
                }
                Err(Errno::ESRCH) => {
                    self.threads.remove(&tid);
                }
                Err(e) => return Err(e).context("PTRACE_CONT"),
            }
        }
        Ok(())
    }

    fn stop_world(&mut self) -> Result<()> {
        let running: Vec<Pid> = self
            .threads
            .iter()
            .filter(|(_, t)| t.running)
            .map(|(p, _)| *p)
            .collect();
        for tid in &running {
            if self.tgkill(*tid, Signal::SIGSTOP).is_ok()
                && let Some(t) = self.threads.get_mut(tid)
            {
                t.sigstop_sent = true;
            }
        }
        for tid in &running {
            while self.threads.get(tid).is_some_and(|t| t.running) {
                let status = self.wait_thread(*tid)?;
                self.handle_status(status)?;
            }
        }
        Ok(())
    }

    fn handle_status(&mut self, status: WaitStatus) -> Result<bool> {
        match status {
            WaitStatus::Exited(tid, code) => {
                self.threads.remove(&tid);
                self.pending_hits.retain(|(p, _)| *p != tid);
                if tid == self.pid {
                    self.exit_code = Some(code);
                }
                Ok(self.threads.is_empty())
            }
            WaitStatus::Signaled(tid, sig, _) => {
                self.threads.remove(&tid);
                self.pending_hits.retain(|(p, _)| *p != tid);
                if tid == self.pid {
                    bail!("inferior killed by signal {:?}", sig);
                }
                Ok(self.threads.is_empty())
            }
            WaitStatus::PtraceEvent(tid, _, event) => {
                self.mark_stopped(tid);
                if event == ptrace::Event::PTRACE_EVENT_CLONE as i32 {
                    let new = Pid::from_raw(ptrace::getevent(tid)? as i32);
                    self.threads.entry(new).or_insert_with(Thread::newly_seen);
                    self.note_thread_count();
                }
                Ok(false)
            }
            WaitStatus::Stopped(tid, Signal::SIGTRAP) => {
                self.mark_stopped(tid);
                let mut regs = ptrace::getregs(tid)?;
                let bp_addr = regs.rip.wrapping_sub(1);
                if self.breakpoints.contains_key(&bp_addr) {
                    regs.rip = bp_addr;
                    ptrace::setregs(tid, regs)?;
                    self.pending_hits.push_back((tid, bp_addr));
                }
                Ok(false)
            }
            WaitStatus::Stopped(tid, Signal::SIGSTOP) => {
                self.mark_stopped(tid);
                if let Some(t) = self.threads.get_mut(&tid) {
                    if t.sigstop_sent {
                        t.sigstop_sent = false; // ours: swallow it
                    } else {
                        t.pending_signal = Some(Signal::SIGSTOP);
                    }
                }
                Ok(false)
            }
            WaitStatus::Stopped(tid, sig) => {
                self.mark_stopped(tid);
                if let Some(t) = self.threads.get_mut(&tid) {
                    t.pending_signal = Some(sig);
                }
                Ok(false)
            }
            other => bail!("unexpected wait status: {:?}", other),
        }
    }

    fn mark_stopped(&mut self, tid: Pid) {
        match self.threads.get_mut(&tid) {
            Some(t) => t.running = false,
            None => {
                self.threads.insert(tid, Thread::newly_seen());
                self.note_thread_count();
            }
        }
    }

    fn tgkill(&self, tid: Pid, sig: Signal) -> Result<()> {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_tgkill,
                self.pid.as_raw(),
                tid.as_raw(),
                sig as i32,
            )
        };
        if rc != 0 {
            bail!(
                "tgkill({}) failed: {}",
                tid,
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    // Methods for mods

    fn ptrace_pid(&self) -> Pid {
        if let Some(c) = self.current
            && self.threads.contains_key(&c)
        {
            return c;
        }
        if self.threads.contains_key(&self.pid) {
            return self.pid;
        }
        self.threads.keys().copied().next().unwrap_or(self.pid)
    }

    pub fn get_reg(&self, name: &str) -> Result<u64> {
        let r = ptrace::getregs(self.ptrace_pid())?;
        Ok(match name {
            "rdi" => r.rdi,
            "rsi" => r.rsi,
            "rdx" => r.rdx,
            "rcx" => r.rcx,
            "r8" => r.r8,
            "r9" => r.r9,
            "rax" => r.rax,
            "rbx" => r.rbx,
            "r10" => r.r10,
            "r11" => r.r11,
            "r12" => r.r12,
            "r13" => r.r13,
            "r14" => r.r14,
            "r15" => r.r15,
            "rsp" => r.rsp,
            "rbp" => r.rbp,
            "rip" => r.rip,
            _ => bail!("unknown register {name}"),
        })
    }

    pub fn set_reg(&self, name: &str, val: u64) -> Result<()> {
        let tid = self.ptrace_pid();
        let mut r = ptrace::getregs(tid)?;
        match name {
            "rdi" => r.rdi = val,
            "rsi" => r.rsi = val,
            "rdx" => r.rdx = val,
            "rcx" => r.rcx = val,
            "r8" => r.r8 = val,
            "r9" => r.r9 = val,
            "rax" => r.rax = val,
            "rbx" => r.rbx = val,
            _ => bail!("cannot set register {name}"),
        }
        ptrace::setregs(tid, r)?;
        Ok(())
    }

    pub fn read_mem(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let tid = self.ptrace_pid();
        let mut out = Vec::with_capacity(len);
        let mut cur = addr;
        while out.len() < len {
            let word = ptrace::read(tid, cur as *mut _)? as u64;
            out.extend_from_slice(&word.to_le_bytes());
            cur += 8;
        }
        out.truncate(len);
        Ok(out)
    }

    pub fn write_mem(&self, addr: u64, bytes: &[u8]) -> Result<()> {
        let tid = self.ptrace_pid();
        let mut i = 0;
        while i < bytes.len() {
            let word_addr = addr + i as u64;
            let mut word = ptrace::read(tid, word_addr as *mut _)? as u64;
            let mut wb = word.to_le_bytes();
            for j in 0..8 {
                if i + j < bytes.len() {
                    wb[j] = bytes[i + j];
                }
            }
            word = u64::from_le_bytes(wb);
            ptrace::write(tid, word_addr as *mut _, word as i64)?;
            i += 8;
        }
        Ok(())
    }
}

mod ptrace_engine;

use anyhow::{Context, Result, bail};
use nix::sys::ptrace;
use nix::unistd::{ForkResult, execv, fork};
use ptrace_engine::{Inferior, Stop};
use rhai::{AST, Array, Dynamic, Engine, EvalAltResult, Scope};
use rrmf_meta::{Metadata, Param, ScalarKind, TypeLayout};
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_interrupt(_sig: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
    let action = SigAction::new(
        SigHandler::Handler(on_interrupt),
        SaFlags::empty(),
        SigSet::empty(),
    );
    unsafe {
        let _ = sigaction(Signal::SIGINT, &action);
        let _ = sigaction(Signal::SIGTERM, &action);
    }
}

type Shared = Arc<Mutex<Inferior>>;

#[derive(Debug)]
struct Hook {
    symbol: String,
    callback: String,
    armed: bool,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: rrmf-launcher <target-binary> <mod.rhai> [target args...]");
        std::process::exit(2);
    }
    let target = std::path::PathBuf::from(&args[1]);
    let mod_path = &args[2];
    let target_args = &args[3..];

    let meta_path = Metadata::path_for_bin(&target);
    let meta = Metadata::load(&meta_path)
        .with_context(|| format!("no RRMF metadata at {}", meta_path.display()))?;
    eprintln!(
        "[launcher] loaded metadata: {} fns, {} types, pie={}",
        meta.functions.len(),
        meta.types.len(),
        meta.pie
    );
    verify_build_id(&target, &meta)?;
    let meta = Arc::new(meta);

    let src = std::fs::read_to_string(mod_path)?;
    let mut engine = Engine::new();
    let hooks = Arc::new(Mutex::new(Vec::<Hook>::new()));
    register_hook_declaration(&mut engine, hooks.clone());
    let ast = engine.compile(&src).context("compiling mod")?;
    let mut scope = Scope::new();
    engine
        .run_ast_with_scope(&mut scope, &ast)
        .context("running mod init")?;
    let hooks: Vec<Hook> = std::mem::take(&mut *hooks.lock().unwrap());
    drop(engine);
    eprintln!("[launcher] mod registered {} hook(s)", hooks.len());

    let index = meta.function_index();
    let mut plan: Vec<(u64, Hook)> = vec![];
    for h in hooks {
        match index.get(h.symbol.as_str()) {
            Some(cands) => {
                let with_addr: Vec<_> = cands.iter().filter(|f| f.address.is_some()).collect();
                if with_addr.is_empty() {
                    eprintln!(
                        "[launcher] WARN symbol '{}' is inline-only ({} inlined copies); \
                         cannot breakpoint an out-of-line entry",
                        h.symbol,
                        cands.iter().map(|f| f.inlined_at.len()).sum::<usize>()
                    );
                    continue;
                }
                if with_addr.len() > 1 {
                    eprintln!(
                        "[launcher] note: '{}' has {} monomorphizations; hooking all",
                        h.symbol,
                        with_addr.len()
                    );
                }
                for f in with_addr {
                    plan.push((
                        f.address.unwrap(),
                        Hook {
                            symbol: h.symbol.clone(),
                            callback: h.callback.clone(),
                            armed: h.armed,
                        },
                    ));
                }
            }
            None => eprintln!("[launcher] WARN unresolved symbol '{}'", h.symbol),
        }
    }
    if plan.is_empty() {
        bail!("no hooks resolved to a breakpointable address");
    }

    match unsafe { fork() }? {
        ForkResult::Child => {
            ptrace::traceme().ok();
            let cpath = CString::new(target.as_os_str().to_string_lossy().as_bytes())?;
            let mut cargs: Vec<CString> = vec![cpath.clone()];
            for a in target_args {
                cargs.push(CString::new(a.as_str())?);
            }
            let _ = execv(&cpath, &cargs);
            std::process::exit(127);
        }
        ForkResult::Parent { child } => {
            run_parent(child, meta, plan)?;
        }
    }
    Ok(())
}

fn run_parent(child: nix::unistd::Pid, meta: Arc<Metadata>, plan: Vec<(u64, Hook)>) -> Result<()> {
    install_signal_handlers();
    let mut inf = Inferior::new(child);
    inf.wait_initial()?;
    let base = inf.resolve_load_base(meta.pie)?;
    eprintln!("[launcher] target load base = {:#x}", base);

    let mut runtime_hooks: HashMap<u64, String> = HashMap::new();
    let mut params: HashMap<u64, Vec<Param>> = HashMap::new();
    let mut by_symbol: HashMap<String, Vec<u64>> = HashMap::new();
    let by_name = meta.function_index();
    for (static_addr, hook) in &plan {
        let rt = inf.set_breakpoint(*static_addr, hook.armed)?;
        runtime_hooks.insert(rt, hook.callback.clone());
        by_symbol.entry(hook.symbol.clone()).or_default().push(rt);
        if let Some(f) = by_name
            .get(hook.symbol.as_str())
            .and_then(|c| c.iter().find(|f| f.address == Some(*static_addr)))
        {
            params.insert(rt, f.params.clone());
        }
        eprintln!(
            "[launcher] breakpoint on {} @ static {:#x} -> runtime {:#x} (cb {}{})",
            hook.symbol,
            static_addr,
            rt,
            hook.callback,
            if hook.armed { "" } else { ", disarmed" }
        );
    }

    let shared: Shared = Arc::new(Mutex::new(inf));

    let (engine, ast) = build_runtime_engine(
        shared.clone(),
        meta.clone(),
        Arc::new(params),
        Arc::new(by_symbol),
    )?;
    let mut scope = Scope::new();

    let mut forwarded_interrupt = false;
    loop {
        let stop = { shared.lock().unwrap().run_to_breakpoint()? };
        if INTERRUPTED.swap(false, Ordering::SeqCst) && !forwarded_interrupt {
            forwarded_interrupt = true;
            eprintln!("[launcher] interrupted; asking the target to shut down");
            let _ = nix::sys::signal::kill(
                shared.lock().unwrap().pid,
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        let (tid, rip) = match stop {
            Stop::Hit(tid, rip) => (tid, rip),
            Stop::Exited => break,
            Stop::Interrupted => continue,
        };
        if let Some(cb) = runtime_hooks.get(&rip) {
            let r: Result<Dynamic, _> = engine.call_fn(&mut scope, &ast, cb, ());
            if let Err(e) = r {
                eprintln!(
                    "[launcher] mod callback '{}' error (thread {}): {}",
                    cb, tid, e
                );
            }
        }
        if !shared.lock().unwrap().is_alive() {
            eprintln!("[launcher] target died while handling a hook");
            break;
        }
        shared.lock().unwrap().step_over(tid, rip)?;
    }

    let inf = shared.lock().unwrap();
    eprintln!(
        "[launcher] target exited with code {} (peak {} threads traced)",
        inf.exit_code.unwrap_or(0),
        inf.peak_threads()
    );
    Ok(())
}

fn verify_build_id(target: &std::path::Path, meta: &Metadata) -> Result<()> {
    let Some(expected) = meta.build_id.as_deref() else {
        return Ok(()); // metadata predates build-id recording
    };
    let data = std::fs::read(target)?;
    let obj = object::File::parse(&*data).context("parsing target binary")?;
    let actual = object::Object::build_id(&obj)
        .ok()
        .flatten()
        .map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<String>());
    match actual {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => bail!(
            "metadata does not match the binary (build-id {} vs {}).\n\
             Re-run `cargo rrmf build`/`extract` -- a plain `cargo build --release` \n\
             rebuilds without the forced debuginfo and invalidates the .rrmf.json.",
            expected,
            actual
        ),
        None => {
            eprintln!("[launcher] WARN target has no build-id; cannot verify metadata matches");
            Ok(())
        }
    }
}

fn register_hook_declaration(engine: &mut Engine, hooks: Arc<Mutex<Vec<Hook>>>) {
    let h = hooks.clone();
    engine.register_fn("hook", move |symbol: &str, callback: &str| {
        h.lock().unwrap().push(Hook {
            symbol: symbol.to_string(),
            callback: callback.to_string(),
            armed: true,
        });
    });
    engine.register_fn("hook_disabled", move |symbol: &str, callback: &str| {
        hooks.lock().unwrap().push(Hook {
            symbol: symbol.to_string(),
            callback: callback.to_string(),
            armed: false,
        });
    });
}

type CallCache = HashMap<(String, Vec<i64>), i64>;
type RefCallCache = HashMap<(String, i64, i64), i64>;

fn build_runtime_engine(
    shared: Shared,
    meta: Arc<Metadata>,
    params: Arc<HashMap<u64, Vec<Param>>>,
    by_symbol: Arc<HashMap<String, Vec<u64>>>,
) -> Result<(Engine, AST)> {
    let mut engine = Engine::new();

    engine.register_fn("hook", |_s: &str, _c: &str| {});
    engine.register_fn("hook_disabled", |_s: &str, _c: &str| {});

    let s = shared.clone();
    let bs = by_symbol.clone();
    engine.register_fn("enable_hook", move |symbol: &str| {
        let Some(addrs) = bs.get(symbol) else {
            eprintln!("[launcher] WARN enable_hook: '{symbol}' is not a declared hook");
            return;
        };
        let mut inf = s.lock().unwrap();
        for a in addrs {
            if let Err(e) = inf.arm(*a) {
                eprintln!("[launcher] enable_hook('{symbol}') failed: {e}");
            }
        }
    });
    let s = shared.clone();
    let bs = by_symbol.clone();
    engine.register_fn("disable_hook", move |symbol: &str| {
        let Some(addrs) = bs.get(symbol) else {
            eprintln!("[launcher] WARN disable_hook: '{symbol}' is not a declared hook");
            return;
        };
        let mut inf = s.lock().unwrap();
        for a in addrs {
            if let Err(e) = inf.disarm(*a) {
                eprintln!("[launcher] disable_hook('{symbol}') failed: {e}");
            }
        }
    });

    let store: Arc<Mutex<HashMap<String, i64>>> = Arc::new(Mutex::new(HashMap::new()));
    let st = store.clone();
    engine.register_fn("set_state", move |key: &str, value: i64| {
        st.lock().unwrap().insert(key.to_string(), value);
    });
    let st = store.clone();
    engine.register_fn("get_state", move |key: &str| -> i64 {
        st.lock().unwrap().get(key).copied().unwrap_or(0)
    });

    let s = shared.clone();
    engine.register_fn("reg", move |name: &str| -> i64 {
        s.lock()
            .unwrap()
            .get_reg(name)
            .map(|v| v as i64)
            .unwrap_or(0)
    });
    let s = shared.clone();
    engine.register_fn("set_reg", move |name: &str, val: i64| {
        let _ = s.lock().unwrap().set_reg(name, val as u64);
    });

    macro_rules! reg_read {
        ($fn:literal, $ty:ty, $len:expr) => {{
            let s = shared.clone();
            engine.register_fn($fn, move |addr: i64| -> i64 {
                let bytes = s
                    .lock()
                    .unwrap()
                    .read_mem(addr as u64, $len)
                    .unwrap_or_default();
                let mut buf = [0u8; 8];
                let n = $len.min(bytes.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                <$ty>::from_le_bytes(buf[..$len].try_into().unwrap()) as i64
            });
        }};
    }
    reg_read!("read_i8", i8, 1);
    reg_read!("read_i32", i32, 4);
    reg_read!("read_i64", i64, 8);

    let s = shared.clone();
    engine.register_fn("read_u64", move |addr: i64| -> i64 {
        let b = s
            .lock()
            .unwrap()
            .read_mem(addr as u64, 8)
            .unwrap_or_default();
        u64::from_le_bytes(b.try_into().unwrap_or([0; 8])) as i64
    });
    let s = shared.clone();
    engine.register_fn("read_f64", move |addr: i64| -> f64 {
        let b = s
            .lock()
            .unwrap()
            .read_mem(addr as u64, 8)
            .unwrap_or_default();
        f64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
    });
    let s = shared.clone();
    engine.register_fn("read_f32", move |addr: i64| -> f64 {
        let b = s
            .lock()
            .unwrap()
            .read_mem(addr as u64, 4)
            .unwrap_or_default();
        f32::from_le_bytes(b.try_into().unwrap_or([0; 4])) as f64
    });

    let s = shared.clone();
    engine.register_fn("mem_readable", move |addr: i64, len: i64| -> bool {
        if addr <= 0 || len <= 0 || len > 4096 {
            return false;
        }
        s.lock()
            .unwrap()
            .read_mem(addr as u64, len as usize)
            .is_ok()
    });

    let s = shared.clone();
    engine.register_fn("read_u16", move |addr: i64| -> i64 {
        let b = s
            .lock()
            .unwrap()
            .read_mem(addr as u64, 2)
            .unwrap_or_default();
        u16::from_le_bytes(b.try_into().unwrap_or([0; 2])) as i64
    });
    let s = shared.clone();
    engine.register_fn("write_u16", move |addr: i64, val: i64| {
        let _ = s
            .lock()
            .unwrap()
            .write_mem(addr as u64, &(val as u16).to_le_bytes());
    });

    let s = shared.clone();
    engine.register_fn("write_i32", move |addr: i64, val: i64| {
        let _ = s
            .lock()
            .unwrap()
            .write_mem(addr as u64, &(val as i32).to_le_bytes());
    });
    let s = shared.clone();
    engine.register_fn("write_i64", move |addr: i64, val: i64| {
        let _ = s.lock().unwrap().write_mem(addr as u64, &val.to_le_bytes());
    });
    let s = shared.clone();
    engine.register_fn("write_u64", move |addr: i64, val: i64| {
        let _ = s
            .lock()
            .unwrap()
            .write_mem(addr as u64, &(val as u64).to_le_bytes());
    });
    let s = shared.clone();
    engine.register_fn("write_f64", move |addr: i64, val: f64| {
        let _ = s.lock().unwrap().write_mem(addr as u64, &val.to_le_bytes());
    });
    let s = shared.clone();
    engine.register_fn("write_f32", move |addr: i64, val: f64| {
        let _ = s
            .lock()
            .unwrap()
            .write_mem(addr as u64, &(val as f32).to_le_bytes());
    });

    let m = meta.clone();
    engine.register_fn("field_offset", move |type_name: &str, field: &str| -> i64 {
        field_lookup(&m, type_name, field)
            .map(|(o, _, _)| o as i64)
            .unwrap_or(-1)
    });
    let m = meta.clone();
    engine.register_fn("field_size", move |type_name: &str, field: &str| -> i64 {
        field_lookup(&m, type_name, field)
            .map(|(_, sz, _)| sz as i64)
            .unwrap_or(-1)
    });

    let s = shared.clone();
    let m = meta.clone();
    engine.register_fn(
        "get_field",
        move |base: i64, type_name: &str, field: &str| -> Dynamic {
            match field_lookup(&m, type_name, field) {
                Some((off, sz, kind)) => {
                    let addr = base as u64 + off;
                    let bytes = s
                        .lock()
                        .unwrap()
                        .read_mem(addr, sz as usize)
                        .unwrap_or_default();
                    scalar_to_dynamic(&bytes, kind)
                }
                None => Dynamic::UNIT,
            }
        },
    );
    let s = shared.clone();
    let m = meta.clone();
    engine.register_fn(
        "set_field",
        move |base: i64, type_name: &str, field: &str, val: i64| {
            if let Some((off, sz, _)) = field_lookup(&m, type_name, field) {
                let addr = base as u64 + off;
                let bytes = (val as u64).to_le_bytes();
                let _ = s.lock().unwrap().write_mem(addr, &bytes[..sz as usize]);
            }
        },
    );

    let s = shared.clone();
    let m = meta.clone();
    engine.register_fn("static_addr", move |name: &str| -> i64 {
        match m.variable_by_name(name) {
            Some(v) => (v.address + s.lock().unwrap().load_base()) as i64,
            None => {
                eprintln!("[launcher] WARN unknown global '{name}'");
                0
            }
        }
    });
    let s = shared.clone();
    let m = meta.clone();
    engine.register_fn("func_addr", move |name: &str| -> i64 {
        let base = s.lock().unwrap().load_base();
        match m
            .functions
            .iter()
            .find(|f| f.name == name && f.address.is_some())
        {
            Some(f) => (f.address.unwrap() + base) as i64,
            None => {
                eprintln!("[launcher] WARN unknown or inline-only function '{name}'");
                0
            }
        }
    });

    let s = shared.clone();
    let m = meta.clone();
    let by_addr: Arc<HashMap<u64, String>> = Arc::new(
        m.variables
            .iter()
            .map(|v| (v.address, v.name.clone()))
            .collect(),
    );
    let ranges: Arc<Vec<(u64, u64, String)>> = Arc::new({
        let mut r: Vec<(u64, u64, String)> = m
            .variables
            .iter()
            .filter(|v| v.size.unwrap_or(0) > 0)
            .map(|v| (v.address, v.address + v.size.unwrap(), v.name.clone()))
            .collect();
        r.sort_by_key(|(a, _, _)| *a);
        r
    });
    engine.register_fn("static_name", move |addr: i64| -> String {
        let base = s.lock().unwrap().load_base();
        let a = (addr as u64).wrapping_sub(base);
        if let Some(n) = by_addr.get(&a) {
            return n.clone();
        }
        match ranges.binary_search_by(|(lo, _, _)| lo.cmp(&a)) {
            Ok(i) => ranges[i].2.clone(),
            Err(0) => String::new(),
            Err(i) => {
                let (lo, hi, name) = &ranges[i - 1];
                if a >= *lo && a < *hi {
                    format!("{name}+{}", a - lo)
                } else {
                    String::new()
                }
            }
        }
    });

    let s = shared.clone();
    engine.register_fn("scratch", move |slot: i64| -> i64 {
        if !(0..(ptrace_engine::SCRATCH_SIZE as i64 / 8)).contains(&slot) {
            eprintln!("[launcher] WARN scratch slot {slot} out of range");
            return 0;
        }
        let rsp = s.lock().unwrap().get_reg("rsp").unwrap_or(0);
        (rsp - ptrace_engine::SCRATCH_OFFSET + slot as u64 * 8) as i64
    });

    let s = shared.clone();
    let m = meta.clone();
    engine.register_fn(
        "invoke",
        move |name: &str, args: Array| -> Result<i64, Box<EvalAltResult>> {
            let base = s.lock().unwrap().load_base();
            let addr = match m
                .functions
                .iter()
                .find(|f| f.name == name && f.address.is_some())
            {
                Some(f) => f.address.unwrap() + base,
                None => return Err(format!("invoke of unknown/inline-only '{name}'").into()),
            };
            Ok(do_call(&s, addr, &args, name)?.0)
        },
    );
    let s = shared.clone();
    engine.register_fn(
        "invoke_addr",
        move |addr: i64, args: Array| -> Result<i64, Box<EvalAltResult>> {
            Ok(do_call(&s, addr as u64, &args, "<addr>")?.0)
        },
    );
    let s = shared.clone();
    let m = meta.clone();
    let cache: Arc<Mutex<CallCache>> = Arc::new(Mutex::new(HashMap::new()));
    engine.register_fn(
        "invoke_cached",
        move |name: &str, args: Array| -> Result<i64, Box<EvalAltResult>> {
            let key: Vec<i64> = args.iter().map(|a| a.as_int().unwrap_or(0)).collect();
            let ck = (name.to_string(), key);
            if let Some(v) = cache.lock().unwrap().get(&ck) {
                return Ok(*v);
            }
            let base = s.lock().unwrap().load_base();
            let addr = match m
                .functions
                .iter()
                .find(|f| f.name == name && f.address.is_some())
            {
                Some(f) => f.address.unwrap() + base,
                None => return Err(format!("invoke_cached of unknown '{name}'").into()),
            };
            let v = do_call(&s, addr, &args, name)?.0;
            cache.lock().unwrap().insert(ck, v);
            Ok(v)
        },
    );

    let s = shared.clone();
    let m = meta.clone();
    let ref_cache: Arc<Mutex<RefCallCache>> = Arc::new(Mutex::new(HashMap::new()));
    engine.register_fn(
        "invoke_ref_cached",
        move |name: &str, value: i64, width: i64| -> Result<i64, Box<EvalAltResult>> {
            if !(1..=8).contains(&width) {
                return Err(format!("invoke_ref_cached width {width} out of range").into());
            }
            let ck = (name.to_string(), value, width);
            if let Some(v) = ref_cache.lock().unwrap().get(&ck) {
                return Ok(*v);
            }
            let (addr, ptr) = {
                let inf = s.lock().unwrap();
                let base = inf.load_base();
                let addr = match m
                    .functions
                    .iter()
                    .find(|f| f.name == name && f.address.is_some())
                {
                    Some(f) => f.address.unwrap() + base,
                    None => return Err(format!("invoke_ref_cached of unknown '{name}'").into()),
                };
                let rsp = match inf.get_reg("rsp") {
                    Ok(v) => v,
                    Err(e) => return Err(format!("rsp unavailable: {e}").into()),
                };
                let ptr = rsp - ptrace_engine::SCRATCH_OFFSET;
                let bytes = (value as u64).to_le_bytes();
                if inf.write_mem(ptr, &bytes[..width as usize]).is_err() {
                    return Err("staging the argument failed".into());
                }
                (addr, ptr)
            };
            let v = do_call(&s, addr, &vec![Dynamic::from(ptr as i64)], name)?.0;
            ref_cache.lock().unwrap().insert(ck, v);
            Ok(v)
        },
    );

    let s = shared.clone();
    let m = meta.clone();
    engine.register_fn(
        "invoke_pair",
        move |name: &str, args: Array| -> Result<Array, Box<EvalAltResult>> {
            let base = s.lock().unwrap().load_base();
            let addr = match m
                .functions
                .iter()
                .find(|f| f.name == name && f.address.is_some())
            {
                Some(f) => f.address.unwrap() + base,
                None => return Err(format!("invoke_pair of unknown '{name}'").into()),
            };
            let (a, d) = do_call(&s, addr, &args, name)?;
            Ok(vec![Dynamic::from(a), Dynamic::from(d)])
        },
    );

    let s = shared.clone();
    let pm = params.clone();
    engine.register_fn("arg", move |index: i64| -> i64 {
        let inf = s.lock().unwrap();
        let Some(bp) = inf.current_bp() else { return 0 };
        let Some(list) = pm.get(&bp) else { return 0 };
        let Some(p) = list.get(index as usize) else {
            eprintln!(
                "[launcher] WARN arg({index}) out of range ({} params)",
                list.len()
            );
            return 0;
        };
        match p.entry_reg.as_deref() {
            Some(spec) => {
                let first = spec.split(':').next().unwrap_or(spec);
                match parse_indirect(first) {
                    Some((reg, off)) => inf
                        .get_reg(reg)
                        .map(|v| v.wrapping_add(off as u64) as i64)
                        .unwrap_or(0),
                    None => inf.get_reg(first).map(|v| v as i64).unwrap_or(0),
                }
            }
            None => {
                eprintln!(
                    "[launcher] WARN arg({index}) ('{}') is not in a register at entry",
                    p.name
                );
                0
            }
        }
    });
    let pm = params.clone();
    let s = shared.clone();
    engine.register_fn("arg_regs", move |index: i64| -> String {
        let bp = match s.lock().unwrap().current_bp() {
            Some(b) => b,
            None => return String::new(),
        };
        pm.get(&bp)
            .and_then(|l| l.get(index as usize))
            .and_then(|p| p.entry_reg.clone())
            .unwrap_or_default()
    });
    let pm = params.clone();
    let s = shared.clone();
    engine.register_fn("arg_count", move || -> i64 {
        let bp = match s.lock().unwrap().current_bp() {
            Some(b) => b,
            None => return 0,
        };
        pm.get(&bp).map(|l| l.len() as i64).unwrap_or(0)
    });

    let s = shared.clone();
    engine.register_fn("dump_regs", move || match s.lock().unwrap().dump_regs() {
        Ok(regs) => {
            let line: Vec<String> = regs.iter().map(|(n, v)| format!("{n}={v:#x}")).collect();
            eprintln!("[mod] regs: {}", line.join(" "));
        }
        Err(e) => eprintln!("[launcher] dump_regs failed: {e}"),
    });

    engine.register_fn("log", |s: &str| eprintln!("[mod] {s}"));

    let src = std::fs::read_to_string(std::env::args().nth(2).unwrap())?;
    let ast = engine.compile(&src)?;
    Ok((engine, ast))
}

fn parse_indirect(spec: &str) -> Option<(&str, i64)> {
    let inner = spec.strip_prefix('[')?.strip_suffix(']')?;
    match inner.find(['+', '-']) {
        Some(i) => Some((&inner[..i], inner[i..].parse().ok()?)),
        None => Some((inner, 0)),
    }
}

fn do_call(
    shared: &Shared,
    addr: u64,
    args: &Array,
    label: &str,
) -> Result<(i64, i64), Box<EvalAltResult>> {
    let raw: Vec<u64> = args
        .iter()
        .map(|a| a.as_int().map(|i| i as u64).unwrap_or(0))
        .collect();
    let mut inf = shared.lock().unwrap();
    if !inf.is_alive() {
        return Err(format!("target is gone; cannot call {label}").into());
    }
    match inf.call_function(addr, &raw) {
        Ok((rax, rdx)) => Ok((rax as i64, rdx as i64)),
        Err(e) => Err(format!("injected call to {label} failed: {e}").into()),
    }
}

fn field_lookup(meta: &Metadata, type_name: &str, field: &str) -> Option<(u64, u64, ScalarKind)> {
    let t: &TypeLayout = meta.type_by_name(type_name)?;
    let f = t.fields.iter().find(|f| f.name == field)?;
    Some((f.offset, f.size, f.kind))
}

fn scalar_to_dynamic(bytes: &[u8], kind: ScalarKind) -> Dynamic {
    let mut buf = [0u8; 8];
    let n = bytes.len().min(8);
    buf[..n].copy_from_slice(&bytes[..n]);
    match kind {
        ScalarKind::Signed => match bytes.len() {
            1 => Dynamic::from(bytes[0] as i8 as i64),
            4 => Dynamic::from(i32::from_le_bytes(buf[..4].try_into().unwrap()) as i64),
            _ => Dynamic::from(i64::from_le_bytes(buf)),
        },
        ScalarKind::Unsigned | ScalarKind::Pointer => Dynamic::from(u64::from_le_bytes(buf) as i64),
        ScalarKind::Bool => Dynamic::from(bytes.first().copied().unwrap_or(0) != 0),
        ScalarKind::Float => match bytes.len() {
            4 => Dynamic::from(f32::from_le_bytes(buf[..4].try_into().unwrap()) as f64),
            _ => Dynamic::from(f64::from_le_bytes(buf)),
        },
        ScalarKind::Other => Dynamic::from(i64::from_le_bytes(buf)),
    }
}

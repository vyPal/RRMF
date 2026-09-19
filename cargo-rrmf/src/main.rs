use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};
use object::{Object, ObjectSection, ObjectSegment};
use rrmf_meta::{
    FORMAT_VERSION, Field, Function, Metadata, Param, ScalarKind, TypeLayout, Variable,
};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    if args.peek().map(|s| s == "rrmf").unwrap_or(false) {
        args.next();
    }
    let sub = args.next().unwrap_or_default();
    let mut crate_filters: Vec<String> = vec![];
    let mut rest = vec![];
    while let Some(a) = args.next() {
        match a.as_str() {
            "--crate" => crate_filters.extend(args.next()),
            "--" => rest.extend(args.by_ref()),
            _ => rest.push(a),
        }
    }

    let bin = match sub.as_str() {
        "build" => {
            let bin = cargo_build(&rest)?;
            eprintln!("[rrmf] built {}", bin.display());
            bin
        }
        "extract" => PathBuf::from(rest.first().context("extract needs a binary path")?),
        _ => bail!(
            "usage: cargo rrmf build [--crate NAME]... [cargo args]\n       cargo rrmf extract [--crate NAME]... <binary>"
        ),
    };

    let data = std::fs::read(&bin)?;
    let obj = object::File::parse(&*data)?;
    let mut stats = Stats::default();
    let meta = extract(&obj, crate_filters, &mut stats)?;
    stats.report(&meta);

    let out = Metadata::path_for_bin(&bin);
    meta.save(&out)?;
    eprintln!(
        "[rrmf] wrote {} ({} functions, {} types, {} variables)",
        out.display(),
        meta.functions.len(),
        meta.types.len(),
        meta.variables.len()
    );
    Ok(())
}

#[derive(Debug, Default)]
struct Stats {
    has_debug_info: bool,
    dwarf_versions: BTreeSet<u16>,
    subprograms_seen: usize,
    variables_seen: usize,
    filtered_out: usize,
    filtered_samples: Vec<String>,
}

impl Stats {
    fn report(&self, meta: &Metadata) {
        if !self.has_debug_info {
            eprintln!("[rrmf] WARN binary has no .debug_info");
            return;
        }
        let with_addr = meta
            .functions
            .iter()
            .filter(|f| f.address.is_some())
            .count();
        eprintln!(
            "[rrmf] DWARF v{:?}: {} subprograms seen, {} kept ({with_addr} with address), {} filtered out",
            self.dwarf_versions,
            self.subprograms_seen,
            meta.functions.len(),
            self.filtered_out
        );
        eprintln!(
            "[rrmf] {} addressable globals seen, {} kept",
            self.variables_seen,
            meta.variables.len()
        );
        if meta.functions.is_empty() && !self.filtered_samples.is_empty() {
            eprintln!("[rrmf] no functions matched the crate filter; sample names seen:");
            for n in &self.filtered_samples {
                eprintln!("\t{n}");
            }
        }
    }
}

fn cargo_build(extra: &[String]) -> Result<PathBuf> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.args([
        "build",
        "--release",
        "--message-format=json-diagnostic-rendered-ansi",
    ])
    .args(extra)
    .env("CARGO_PROFILE_RELEASE_DEBUG", "2")
    .env("CARGO_PROFILE_RELEASE_STRIP", "none")
    .env("CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO", "off")
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit());
    let mut child = cmd.spawn().context("failed to spawn cargo")?;
    let stdout = child.stdout.take().unwrap();

    let mut exe = None;
    for line in BufReader::new(stdout).lines() {
        let line = line?;
        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                println!("{line}");
                continue;
            }
        };
        match v["reason"].as_str() {
            Some("compiler-message") => {
                if let Some(r) = v["message"]["rendered"].as_str() {
                    eprintln!("{r}");
                }
            }
            Some("compiler-artifact") => {
                if let Some(e) = v["executable"].as_str() {
                    exe = Some(PathBuf::from(e));
                }
            }
            _ => {}
        }
    }

    if !child.wait()?.success() {
        bail!("cargo build failed");
    }
    exe.context("cargo produced no executable artifact")
}

fn extract(obj: &object::File, crate_filter: Vec<String>, stats: &mut Stats) -> Result<Metadata> {
    let pie = obj.kind() == object::ObjectKind::Dynamic;
    let image_base = obj.segments().map(|s| s.address()).min().unwrap_or(0);
    let build_id = obj.build_id().ok().flatten().map(hex);
    stats.has_debug_info = obj.section_by_name(".debug_info").is_some();

    let endian = gimli::RunTimeEndian::Little;
    let load = |id: gimli::SectionId| -> Result<std::borrow::Cow<[u8]>> {
        Ok(obj
            .section_by_name(id.name())
            .and_then(|s| s.uncompressed_data().ok())
            .unwrap_or(std::borrow::Cow::Borrowed(&[])))
    };
    let dwarf_sections = gimli::DwarfSections::load(&load)?;
    let dwarf = dwarf_sections.borrow(|s| gimli::EndianSlice::new(s, endian));

    let mut functions: BTreeMap<String, Function> = BTreeMap::new();
    let mut types: BTreeMap<String, TypeLayout> = BTreeMap::new();
    let mut variables: BTreeMap<String, Variable> = BTreeMap::new();

    let prefixes: Vec<String> = crate_filter.iter().map(|c| format!("{c}::")).collect();
    let matches_filter = |name: &str| {
        if prefixes.is_empty() {
            return true;
        }
        let bare = name.trim_start_matches('<');
        prefixes.iter().any(|p| bare.starts_with(p.as_str()))
    };

    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        stats.dwarf_versions.insert(header.version());
        let unit = dwarf.unit(header)?;
        walk_unit(
            &dwarf,
            &unit,
            &matches_filter,
            &mut functions,
            &mut types,
            &mut variables,
            stats,
        )?;
    }

    Ok(Metadata {
        format_version: FORMAT_VERSION,
        crate_filter,
        build_id,
        pie,
        image_base,
        functions: functions.into_values().collect(),
        types: types.into_values().collect(),
        variables: variables.into_values().collect(),
    })
}

type Reader<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;

fn walk_unit(
    dwarf: &gimli::Dwarf<Reader>,
    unit: &gimli::Unit<Reader>,
    keep: &dyn Fn(&str) -> bool,
    functions: &mut BTreeMap<String, Function>,
    types: &mut BTreeMap<String, TypeLayout>,
    variables: &mut BTreeMap<String, Variable>,
    stats: &mut Stats,
) -> Result<()> {
    let mut tree = unit.entries_tree(None)?;
    let root = tree.root()?;
    let mut ns: Vec<String> = vec![];
    walk_node(
        dwarf, unit, root, &mut ns, keep, functions, types, variables, stats,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_node<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    node: gimli::EntriesTreeNode<Reader<'a>>,
    ns: &mut Vec<String>,
    keep: &dyn Fn(&str) -> bool,
    functions: &mut BTreeMap<String, Function>,
    types: &mut BTreeMap<String, TypeLayout>,
    variables: &mut BTreeMap<String, Variable>,
    stats: &mut Stats,
) -> Result<()> {
    let entry = node.entry();
    let tag = entry.tag();
    let mut pushed = false;

    match tag {
        gimli::DW_TAG_namespace => {
            if let Some(n) = attr_str(dwarf, unit, entry, gimli::DW_AT_name)? {
                ns.push(n);
                pushed = true;
            }
        }
        gimli::DW_TAG_subprogram => {
            if let Some(f) = read_subprogram(dwarf, unit, entry)? {
                stats.subprograms_seen += 1;
                if keep(&f.name) {
                    merge_fn(functions, f);
                } else {
                    stats.filtered_out += 1;
                    if stats.filtered_samples.len() < 8 && f.address.is_some() {
                        stats.filtered_samples.push(f.name);
                    }
                }
            }
        }
        gimli::DW_TAG_inlined_subroutine => {
            if let Some((name, low)) = read_inlined(dwarf, unit, entry)?
                && keep(&name)
            {
                functions
                    .entry(name.clone())
                    .or_insert_with(|| Function {
                        name,
                        linkage_name: None,
                        address: None,
                        size: None,
                        inlined_at: vec![],
                        params: vec![],
                    })
                    .inlined_at
                    .push(low);
            }
        }
        gimli::DW_TAG_variable => {
            if let Some(v) = read_variable(dwarf, unit, entry, ns)? {
                stats.variables_seen += 1;
                if keep(&v.name) {
                    variables.entry(v.name.clone()).or_insert(v);
                }
            }
        }
        gimli::DW_TAG_structure_type
        | gimli::DW_TAG_union_type
        | gimli::DW_TAG_enumeration_type => {
            if let Some(t) = read_struct(dwarf, unit, entry, ns)?
                && keep(&t.name)
            {
                types.entry(t.name.clone()).or_insert(t);
            }
        }
        _ => {}
    }

    let mut children = node.children();
    while let Some(child) = children.next()? {
        walk_node(
            dwarf, unit, child, ns, keep, functions, types, variables, stats,
        )?;
    }
    if pushed {
        ns.pop();
    }
    Ok(())
}

fn merge_fn(map: &mut BTreeMap<String, Function>, mut f: Function) {
    match map.get_mut(&f.name) {
        Some(existing) => {
            if existing.address.is_none() && f.address.is_some() {
                existing.address = f.address;
                existing.size = f.size;
                existing.params = std::mem::take(&mut f.params);
                existing.linkage_name = existing.linkage_name.take().or(f.linkage_name);
            }
            existing.inlined_at.extend(f.inlined_at);
        }
        None => {
            map.insert(f.name.clone(), f);
        }
    }
}

fn attr_str<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    entry: &gimli::DebuggingInformationEntry<Reader<'a>>,
    attr: gimli::DwAt,
) -> Result<Option<String>> {
    if let Some(a) = entry.attr(attr)
        && let Ok(s) = dwarf.attr_string(unit, a.value())
    {
        return Ok(Some(s.to_string_lossy().into_owned()));
    }
    Ok(None)
}

fn attr_u64(entry: &gimli::DebuggingInformationEntry<Reader>, attr: gimli::DwAt) -> Option<u64> {
    entry.attr_value(attr).and_then(|v| match v {
        gimli::AttributeValue::Udata(u) => Some(u),
        gimli::AttributeValue::Data1(u) => Some(u as u64),
        gimli::AttributeValue::Data2(u) => Some(u as u64),
        gimli::AttributeValue::Data4(u) => Some(u as u64),
        gimli::AttributeValue::Data8(u) => Some(u),
        gimli::AttributeValue::Sdata(i) => Some(i as u64),
        _ => None,
    })
}

fn resolve_fn_name<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    entry: &gimli::DebuggingInformationEntry<Reader<'a>>,
    depth: u32,
) -> Result<(Option<String>, Option<String>)> {
    if let Some(link) = attr_str(dwarf, unit, entry, gimli::DW_AT_linkage_name)? {
        let pretty = demangle_clean(&link);
        return Ok((Some(link), Some(pretty)));
    }
    if depth < 4 {
        for at in [gimli::DW_AT_specification, gimli::DW_AT_abstract_origin] {
            if let Some(gimli::AttributeValue::UnitRef(off)) = entry.attr_value(at) {
                let refd = unit.entry(off)?;
                let (l, p) = resolve_fn_name(dwarf, unit, &refd, depth + 1)?;
                if p.is_some() {
                    return Ok((l, p));
                }
            }
        }
    }
    if let Some(n) = attr_str(dwarf, unit, entry, gimli::DW_AT_name)? {
        return Ok((None, Some(n)));
    }
    Ok((None, None))
}

fn read_subprogram<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    entry: &gimli::DebuggingInformationEntry<Reader<'a>>,
) -> Result<Option<Function>> {
    let (linkage, pretty) = resolve_fn_name(dwarf, unit, entry, 0)?;
    let name = match pretty {
        Some(n) => n,
        None => return Ok(None),
    };
    let low = read_addr(dwarf, unit, entry, gimli::DW_AT_low_pc)?.filter(|&a| a != 0);
    let size = match (low, entry.attr_value(gimli::DW_AT_high_pc)) {
        (None, _) | (_, None) => None,
        (Some(_), Some(v)) if v.udata_value().is_some() => v.udata_value(),
        (Some(lo), Some(_)) => {
            read_addr(dwarf, unit, entry, gimli::DW_AT_high_pc)?.map(|hi| hi.saturating_sub(lo))
        }
    };
    let params = if low.is_some() {
        read_params(dwarf, unit, entry, low.unwrap_or(0))?
    } else {
        vec![]
    };
    Ok(Some(Function {
        name,
        linkage_name: linkage,
        address: low,
        size,
        inlined_at: vec![],
        params,
    }))
}

// DWARF register numbers for x86-64, per the psABI. Index = DW_OP_regN.
const X86_64_DWARF_REGS: [&str; 17] = [
    "rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15", "rip",
];

fn dwarf_reg_name(n: u16) -> Option<String> {
    X86_64_DWARF_REGS.get(n as usize).map(|s| (*s).to_string())
}

fn expr_entry_reg(expr: gimli::Expression<Reader>, encoding: gimli::Encoding) -> Option<String> {
    let mut ops = expr.operations(encoding);
    let mut regs: Vec<String> = vec![];
    while let Ok(Some(op)) = ops.next() {
        match op {
            gimli::Operation::Register { register } => {
                if let Some(n) = dwarf_reg_name(register.0) {
                    regs.push(n);
                }
            }
            gimli::Operation::Piece { .. } => {}
            gimli::Operation::RegisterOffset {
                register, offset, ..
            } => {
                let name = dwarf_reg_name(register.0)?;
                regs.push(if offset == 0 {
                    format!("[{name}]")
                } else {
                    format!("[{name}{offset:+}]")
                });
            }
            _ => return None,
        }
    }
    if regs.is_empty() {
        None
    } else {
        Some(regs.join(":"))
    }
}

fn read_params<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    entry: &gimli::DebuggingInformationEntry<Reader<'a>>,
    low_pc: u64,
) -> Result<Vec<Param>> {
    let mut params = vec![];
    let mut tree = unit.entries_tree(Some(entry.offset()))?;
    let root = tree.root()?;
    let mut children = root.children();
    while let Some(child) = children.next()? {
        let e = child.entry();
        if e.tag() != gimli::DW_TAG_formal_parameter {
            continue;
        }
        let name = attr_str(dwarf, unit, e, gimli::DW_AT_name)?.unwrap_or_default();
        let (type_name, size) = match e.attr_value(gimli::DW_AT_type) {
            Some(gimli::AttributeValue::UnitRef(off)) => {
                let ty = unit.entry(off)?;
                (
                    attr_str(dwarf, unit, &ty, gimli::DW_AT_name)?
                        .unwrap_or_else(|| "<anon>".into()),
                    attr_u64(&ty, gimli::DW_AT_byte_size),
                )
            }
            _ => ("<unknown>".into(), None),
        };

        let entry_reg = match e.attr_value(gimli::DW_AT_location) {
            Some(gimli::AttributeValue::Exprloc(expr)) => expr_entry_reg(expr, unit.encoding()),
            Some(other) => match dwarf.attr_locations(unit, other)? {
                Some(mut list) => {
                    let mut covering = None;
                    let mut earliest: Option<(u64, Option<String>)> = None;
                    while let Some(loc) = list.next()? {
                        let reg = expr_entry_reg(loc.data, unit.encoding());
                        if loc.range.begin <= low_pc && low_pc < loc.range.end {
                            covering = reg;
                            break;
                        }
                        if earliest.as_ref().is_none_or(|(b, _)| loc.range.begin < *b) {
                            earliest = Some((loc.range.begin, reg));
                        }
                    }
                    covering.or_else(|| earliest.and_then(|(_, r)| r))
                }
                None => None,
            },
            None => None,
        };
        params.push(Param {
            name,
            type_name,
            size,
            entry_reg,
        });
    }
    Ok(params)
}

fn read_inlined<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    entry: &gimli::DebuggingInformationEntry<Reader<'a>>,
) -> Result<Option<(String, u64)>> {
    let name = if let Some(gimli::AttributeValue::UnitRef(off)) =
        entry.attr_value(gimli::DW_AT_abstract_origin)
    {
        let origin = unit.entry(off)?;
        let (_, p) = resolve_fn_name(dwarf, unit, &origin, 0)?;
        match p {
            Some(n) => n,
            None => return Ok(None),
        }
    } else {
        return Ok(None);
    };
    // Inlined copies sometimes use DW_AT_ranges instead of low_pc
    let low = match read_addr(dwarf, unit, entry, gimli::DW_AT_low_pc)? {
        Some(a) if a != 0 => a,
        _ => match dwarf.die_ranges(unit, entry)?.next()? {
            Some(r) if r.begin != 0 => r.begin,
            _ => return Ok(None),
        },
    };
    Ok(Some((name, low)))
}

fn read_variable<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    entry: &gimli::DebuggingInformationEntry<Reader<'a>>,
    ns: &[String],
) -> Result<Option<Variable>> {
    if entry.attr_value(gimli::DW_AT_declaration).is_some() {
        return Ok(None);
    }
    let Some(gimli::AttributeValue::Exprloc(expr)) = entry.attr_value(gimli::DW_AT_location) else {
        return Ok(None);
    };
    let mut ops = expr.operations(unit.encoding());
    let address = match ops.next()? {
        Some(gimli::Operation::Address { address }) => address,
        Some(gimli::Operation::AddressIndex { index }) => dwarf.address(unit, index)?,
        _ => return Ok(None),
    };
    if address == 0 {
        return Ok(None);
    }
    let local = match attr_str(dwarf, unit, entry, gimli::DW_AT_name)? {
        Some(n) => n,
        None => return Ok(None),
    };
    let name = if ns.is_empty() {
        local
    } else {
        format!("{}::{}", ns.join("::"), local)
    };
    let linkage_name = attr_str(dwarf, unit, entry, gimli::DW_AT_linkage_name)?;

    let (type_name, size) = match entry.attr_value(gimli::DW_AT_type) {
        Some(gimli::AttributeValue::UnitRef(off)) => {
            let ty = unit.entry(off)?;
            (
                attr_str(dwarf, unit, &ty, gimli::DW_AT_name)?.unwrap_or_else(|| "<anon>".into()),
                attr_u64(&ty, gimli::DW_AT_byte_size),
            )
        }
        _ => ("<unknown>".into(), None),
    };

    Ok(Some(Variable {
        name,
        linkage_name,
        address,
        size,
        type_name,
    }))
}

fn read_struct<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    entry: &gimli::DebuggingInformationEntry<Reader<'a>>,
    ns: &[String],
) -> Result<Option<TypeLayout>> {
    let local = match attr_str(dwarf, unit, entry, gimli::DW_AT_name)? {
        Some(n) => n,
        None => return Ok(None),
    };
    let size = match attr_u64(entry, gimli::DW_AT_byte_size) {
        Some(s) => s,
        None => return Ok(None),
    };
    let align = attr_u64(entry, gimli::DW_AT_alignment);
    let name = if ns.is_empty() {
        local
    } else {
        format!("{}::{}", ns.join("::"), local)
    };

    let mut fields = vec![];
    let mut tree = unit.entries_tree(Some(entry.offset()))?;
    let root = tree.root()?;
    let mut children = root.children();
    while let Some(child) = children.next()? {
        let e = child.entry();
        if e.tag() != gimli::DW_TAG_member {
            continue;
        }
        let fname = attr_str(dwarf, unit, e, gimli::DW_AT_name)?.unwrap_or_default();
        let offset = attr_u64(e, gimli::DW_AT_data_member_location).unwrap_or(0);
        let (type_name, fsize, kind) = resolve_member_type(dwarf, unit, e)?;
        fields.push(Field {
            name: fname,
            offset,
            size: fsize,
            type_name,
            kind,
        });
    }
    fields.sort_by_key(|f| f.offset);
    Ok(Some(TypeLayout {
        name,
        size,
        align,
        fields,
    }))
}

fn resolve_member_type<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    member: &gimli::DebuggingInformationEntry<Reader<'a>>,
) -> Result<(String, u64, ScalarKind)> {
    if let Some(gimli::AttributeValue::UnitRef(off)) = member.attr_value(gimli::DW_AT_type) {
        let ty = unit.entry(off)?;
        let tname =
            attr_str(dwarf, unit, &ty, gimli::DW_AT_name)?.unwrap_or_else(|| "<anon>".into());
        let mut tsize = attr_u64(&ty, gimli::DW_AT_byte_size).unwrap_or(0);
        let kind = if ty.tag() == gimli::DW_TAG_pointer_type {
            ScalarKind::Pointer
        } else if ty.tag() == gimli::DW_TAG_base_type {
            let enc = match ty.attr_value(gimli::DW_AT_encoding) {
                Some(gimli::AttributeValue::Encoding(e)) => Some(e.0 as u16),
                other => other.and_then(|v| match v {
                    gimli::AttributeValue::Udata(u) => Some(u as u16),
                    gimli::AttributeValue::Data1(u) => Some(u as u16),
                    _ => None,
                }),
            };
            match enc {
                Some(0x02) => ScalarKind::Bool,
                Some(0x04) => ScalarKind::Float,
                Some(0x05) => ScalarKind::Signed,
                Some(0x07) | Some(0x08) => ScalarKind::Unsigned,
                _ => ScalarKind::Other,
            }
        } else {
            ScalarKind::Other
        };
        if kind == ScalarKind::Pointer && tsize == 0 {
            tsize = 8;
        }
        return Ok((tname, tsize, kind));
    }
    Ok(("<unknown>".into(), 0, ScalarKind::Other))
}

fn read_addr<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    entry: &gimli::DebuggingInformationEntry<Reader<'a>>,
    attr: gimli::DwAt,
) -> Result<Option<u64>> {
    Ok(match entry.attr_value(attr) {
        Some(v @ (gimli::AttributeValue::Addr(_) | gimli::AttributeValue::DebugAddrIndex(_))) => {
            dwarf.attr_address(unit, v)?
        }
        _ => None,
    })
}

fn demangle_clean(sym: &str) -> String {
    let s = format!("{:#}", rustc_demangle::demangle(sym));
    let s = strip_hash(&s);
    if let Some(rest) = s.strip_prefix('<') {
        let mut depth = 1;
        for (i, c) in rest.char_indices() {
            match c {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        let inner = &rest[..i];
                        let tail = &rest[i + 1..];
                        if !has_top_level_as(inner) && tail.starts_with("::") {
                            return format!("{inner}{tail}");
                        }
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    s
}

fn has_top_level_as(s: &str) -> bool {
    let mut depth = 0;
    let b = s.as_bytes();
    for i in 0..b.len() {
        match b[i] {
            b'<' | b'(' | b'[' => depth += 1,
            b'>' | b')' | b']' => depth -= 1,
            b' ' if depth == 0 && s[i..].starts_with(" as ") => return true,
            _ => {}
        }
    }
    false
}

fn strip_hash(s: &str) -> String {
    if let Some(idx) = s.rfind("::h") {
        let tail = &s[idx + 3..];
        if tail.len() >= 8 && tail.chars().all(|c| c.is_ascii_hexdigit()) {
            return s[..idx].to_string();
        }
    }
    s.to_string()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

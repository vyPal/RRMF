# RRMF

A runtime modding framework for Rust programs, built on ptrace. No source changes or recompiling the target needed, just debug info.

Mods are [Rhai](https://rhai.rs) scripts that hook functions in a running binary.

## How it works

1. `cargo rrmf build` builds your target and dumps its DWARF info (functions, struct layouts, statics) into a metadata file next to the binary.
2. `rrmf-launcher` starts the binary under ptrace, sets breakpoints on the functions your mod hooks, and runs your script when they hit.

## Usage

```
cargo rrmf build [--crate NAME]... [cargo args]
rrmf-launcher <binary> <mod.rhai> [args...]
```

A mod looks like this:

```rhai
hook("my_crate::Foo::bar", "on_bar");

fn on_bar() {
    // poke at memory, registers, call functions...
}
```

See `example-mods/` for a demo built for the SteelMC minecraft server software

## Caveats

- Linux x86-64 only.
- Rust has no stable ABI, so mods will generally break once the hooked source changes
- Very much a work in progress.

## License

See [LICENSE](LICENSE).

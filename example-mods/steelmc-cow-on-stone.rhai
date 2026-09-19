// EntityRegistry::create(&self, entity_type, entity_id, pos: DVec3, world)
//   rdi = entries.as_ptr()      <- `&self` is SROA'd into its two fields:
//   rsi = entries.len()            EntityRegistry is a single Vec, and the body
//                                  only uses ptr and len
//   rdx = entity_type           <- &'static EntityType
//   rcx = entity_id             <- i32, used as %ecx
//   r8  = *const DVec3          <- passed indirectly
//   r9  = world: Weak<World>
//   -> Option<Arc<dyn Entity>> in rax:rdx (tail is `xor %eax,%eax; ret`, so
//      None is rax == 0 and there is no sret)
//
// World::try_add_entity(&Arc<World>, entity)
//   rdi = sret (Result<(), AddEntityError>, 24-byte error payload)
//   rsi = the ArcInner pointer itself, NOT a pointer to the Arc. DWARF says
//         `&Arc<World>` and gives no location; the body does `mov 0x58(%rsi)`
//         to reach `chunk_map` (World offset 0x48 + the 0x10 ArcInner header).
//         Passing the &Arc segfaults inside the chunk lookup.
//   rdx = entity data ptr    Arc<dyn Entity> is a fat pointer; `call *0xa8 (%rcx)` 
//   rcx = entity vtable ptr  in the body proves rcx is the vtable.
//
// World::tick_game(&Arc<World>, tick_count, runs_normally)
//   rdi = sret (WorldGameTickTimings), rsi = &Arc<World>

hook("steel_core::player::game_mode::item_interaction::use_item_on", "on_player_use");
hook_disabled("steel_core::world::World::set_block_with_limit", "on_set_block");
hook_disabled("steel_core::world::World::tick_game", "on_tick");

const SET_BLOCK  = "steel_core::world::World::set_block_with_limit";
const GET_BLOCK  = "<steel_utils::types::codec_glue::BlockStateId as steel_registry::blocks::block_state_ext::BlockStateExt>::get_block";
const CREATE     = "steel_core::entity::registry::EntityRegistry::create";
const NEXT_ID    = "steel_core::entity::next_entity_id";
const TRY_ADD    = "steel_core::world::World::try_add_entity";
const TICK       = "steel_core::world::World::tick_game";
const MOB        = "steel_registry::vanilla_entities::COW";

fn on_player_use() {
  set_state("budget", 12);
  enable_hook(global::SET_BLOCK);
}

fn on_set_block() {
  let state = arg(2);
  let block = invoke_ref_cached(global::GET_BLOCK, state, 2);

  if block != static_addr("steel_registry::vanilla_blocks::STONE") {
    let budget = get_state("budget") - 1;
    set_state("budget", budget);
    if budget <= 0 { disable_hook(global::SET_BLOCK); }
    return;
  }

  let world_ref = arg(0);
  let pos_ptr   = arg(1);
  let x = read_i32(pos_ptr);
  let y = read_i32(pos_ptr + 4);
  let z = read_i32(pos_ptr + 8);
  log("stone placed at (" + x + "," + y + "," + z + ") -- queueing a cow");

  set_state("want_x", x);
  set_state("want_y", y);
  set_state("want_z", z);
  set_state("want_world", read_u64(world_ref));
  set_state("pending", 1);

  set_state("budget", 0);
  disable_hook(global::SET_BLOCK);
  enable_hook(global::TICK);
}

fn on_tick() {
  if get_state("pending") == 0 {
    disable_hook(global::TICK);
    return;
  }
  let world_ref = arg(0);
  if read_u64(world_ref) != get_state("want_world") {
    return;
  }
  set_state("pending", 0);
  disable_hook(global::TICK);

  spawn_mob(world_ref, get_state("want_x"), get_state("want_y"), get_state("want_z"));
}

fn spawn_mob(world_ref, x, y, z) {
  // --- 1. the entity registry's backing slice, read out of the static ---
  //
  // `ENTITIES` is `EntityRegistryLock(OnceLock<EntityRegistry>)`, and the
  // layout of neither `OnceLock` nor `Vec` is in the metadata: both come from
  // std, which the crate filter excludes, and neither has a guaranteed field
  // order.
  //
  // The call site states the answer outright. Disassembling
  // `summon::create_entity`, which does exactly this load before calling
  // `create`:
  //
  //     mov ENTITIES+0x8,  %rdi     ; entries.as_ptr()
  //     mov ENTITIES+0x10, %rsi     ; entries.len()
  //
  // (so the Vec sits at offset 0 as cap@0, ptr@8, len@16, with the OnceLock
  // state after it at +0x18). When a layout is not in the metadata, read it
  // off a caller rather than inferring it from the values.
  let lock = static_addr("steel_core::entity::registry::ENTITIES");
  if lock == 0 { log("  ! ENTITIES static not in metadata"); return; }
  let entries_ptr = read_u64(lock + 8);
  let entries_len = read_u64(lock + 16);

  if !mem_readable(entries_ptr, 16) {
    log("  ! registry pointer not readable: " + entries_ptr);
    return;
  }
  if entries_len <= 0 || entries_len > 100000 {
    log("  ! implausible registry length " + entries_len);
    return;
  }
  log("  registry: ptr=" + entries_ptr + " len=" + entries_len);

  let mob = static_addr(global::MOB);
  if mob == 0 { log("  ! " + global::MOB + " not in metadata"); return; }

  // --- 2. a fresh entity id ---
  // Returns i32 in eax; mask, since the upper half of rax is not guaranteed
  // to be cleared for a 32-bit return.
  let entity_id = invoke(global::NEXT_ID, []) & 0xffffffff;
  log("  entity_id=" + entity_id);

  // --- 3. position, staged for the indirect DVec3 argument ---
  // Centre of the block above the one just placed.
  let pos = scratch(0);                       // 24 bytes
  write_f64(pos,      x + 0.5);
  write_f64(pos + 8,  y + 1.0);
  write_f64(pos + 16, z + 0.5);

  // --- 4. a Weak<World> ---
  // `Weak<T>` and `Arc<T>` are both pointers to the same ArcInner
  // { strong: usize, weak: usize, data: T }. Handing the entity a Weak means
  // a weak reference now exists, so its count must be incremented -- the
  // entity will decrement it when dropped, and skipping this would corrupt
  // the refcount. Safe to do non-atomically: the world is stopped here.
  let arc_inner = read_u64(world_ref);
  if !mem_readable(arc_inner, 16) { log("  ! world Arc not readable"); return; }
  let weak_count = read_u64(arc_inner + 8);
  write_u64(arc_inner + 8, weak_count + 1);

  // --- 5. build the entity ---
  let created = invoke_pair(global::CREATE, [entries_ptr, entries_len, mob, entity_id, pos, arc_inner]);
  let data = created[0];
  let vtable = created[1];
  if data == 0 {
    log("  ! create returned None (no factory for this entity type)");
    write_u64(arc_inner + 8, weak_count);   // undo the weak increment
    return;
  }
  log("  created entity: data=" + data + " vtable=" + vtable);

  // --- 6. add it to the world ---
  // try_add_entity takes the Arc by value, so the strong reference created
  // above moves into the world; nothing to undo on success.
  let sret = scratch(8);                      // 32 bytes for Result<(), AddEntityError>
  write_u64(sret, 0);
  write_u64(sret + 8, 0);
  write_u64(sret + 16, 0);
  write_u64(sret + 24, 0);
  invoke(global::TRY_ADD, [sret, arc_inner, data, vtable]);
  // Result<(), AddEntityError>: the discriminant is the low 32 bits. Read off
  // the function's own epilogue, `movl $0xffffffff,(%rax)` marks Ok. Tag 0 is
  // the chunk-not-loaded arm, which carries the chunk x/z at +8 / +12.
  let tag = read_u64(sret) & 0xffffffff;
  if tag == 0xffffffff {
    log("  cow spawned at (" + x + "," + (y + 1) + "," + z + ")");
  } else if tag == 0 {
    log("  ! try_add_entity: chunk (" + read_i32(sret + 8) + "," + read_i32(sret + 12) + ") is not loaded");
  } else {
    log("  ! try_add_entity refused the entity, error tag " + tag);
  }
}

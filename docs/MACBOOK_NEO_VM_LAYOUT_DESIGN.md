# MacBook Neo 8 GB VM layout qualification

Status: **source candidate implemented, not physically qualified or admitted**. The existing
three-VM allocation is 2 GiB Gateway, 6 GiB Research, and 4 GiB Target.
`scripts/vm-maintenance.py` hard-codes it, and the resource discussion in
`DESIGN.md` assumes a 24 GB MacBook Air. Do not provision that layout on an
8 GB Neo or treat this candidate as an installed release.

## Boundary to preserve

Gateway, Research, and Target remain three separate ARM64 Ubuntu Server VMs
with the same networks, guest sharing disabled, fixed credentials, and
independent readback. No guest may be merged into the host or another guest.
Do not enable dynamic memory or host integration to compensate for the smaller
machine. The candidate changes only CPU and static RAM allocations; disks and
containment policy remain as designed.

## Candidate for measurement

| VM | Current vCPU / RAM | Neo candidate vCPU / RAM | Disk |
| --- | ---: | ---: | ---: |
| Gateway | 1 / 2 GiB | 1 / 1.5 GiB | 12 GiB |
| Research | 4 / 6 GiB | 2 / 2.5 GiB | 50 GiB |
| Target | 2 / 4 GiB | 1 / 1.5 GiB | 40 GiB |
| Total | 7 / 12 GiB | 4 / 5.5 GiB | 102 GiB virtual |

The candidate leaves 2.5 GiB of nominal physical RAM for macOS, Parallels,
and overhead. [Ubuntu's 26.04 release notes](https://documentation.ubuntu.com/release-notes/26.04/)
say Server requirements can start at 1.5 GB RAM, depending on workload. That
is an operating-system starting point, not evidence that Gateway, Research,
or Target services fit these allocations. The Research workload is the main
unknown. [Parallels' CPU and memory guidance](https://docs.parallels.com/landing/pdfm-ug/v20-en-us/parallels-desktop-for-mac-20-users-guide/parallels-desktop-preferences-and-virtual-machine-settings/virtual-machine-settings/hardware-settings/cpu-and-memory-settings)
also calls for measuring the actual workload. No production or acceptance
claim follows from this table.

## Source implementation and remaining review

The source now requires an explicit `--layout-profile neo-8gb` on
`scripts/vm-operation.py` for a Neo plan. It binds the profile, all CPU/RAM/disk
values, and physical host memory into the plan digest and displayed
authorization parameters. Execution re-reads host memory and rebuilds the
plan before VM mutation. The existing `standard` layout stays the default;
the 8 GB host rejects that layout, while larger hosts reject `neo-8gb`.
Creation independently reads back CPU and RAM as well as the existing
isolation settings. Reprovision refuses a layout transition; an explicit
reviewed migration path is still required if that ever becomes necessary.
This source is committed on the local `neo-8gb-vm-layout` branch. The full
exact-candidate check has not passed on this Mac, and the candidate has not
passed physical Parallels 27 readback. A protected release must be built from
the reviewed commit before any qualified VM creation.

## Physical qualification order

1. Build, review, and publish one exact candidate commit through the normal
   public-release gates on the trusted release Mac.
2. Start from a freshly erased dedicated Neo and new local test account.
   Confirm absence of provider and production material with the project
   enrollment check. Close Parallels Desktop's GUI before VM lifecycle work.
   The pre-install morning gate accepts an empty Parallels inventory only for
   the exact protected Host bootstrap; it rejects a partial VM set.
3. Install the exact protected Host closure from that preflight. Retain the
   morning-preflight and installer receipts; do not use an operator-writable
   checkout as privileged source. Create all three VMs through the reviewed
   plan and independently read back CPU, RAM, disk, networks, sharing, and
   stopped state. Never accept the
   `prlctl set` response alone as proof.
4. Measure host `memory_pressure -Q`, `sysctl vm.swapusage`, and VM and Host
   process state before boot, after each guest boot, and with all three guests
   running. Retain timed samples and any macOS memory-pressure or guest OOM
   evidence. If the host or a guest cannot run stably, stop and revise the
   candidate rather than masking pressure with swap or dynamic memory.
5. Run the full Gateway, Research, and Target service stack and representative
   bounded Research and Target work. Verify all network and credential
   boundaries independently, including fail-closed behavior during pressure,
   service restart, Research-only hard power, and cold boot.
6. Re-run the morning preflight with all three VMs present. Only after the
   resource and boundary runs pass, run the ordered 91-case,
   198-observation disposable harness campaign and independent off-machine
   evidence verification described in
   `DISPOSABLE_MAC_OPERATOR_CEREMONY_QUEUE.md`. The campaign must bind the
   exact Neo layout commit and machine. Source tests and a booted VM are not
   substitutes for this result.

## Current Neo observation

The 2026-11-06 read-only probe found 8 GiB physical RAM, about 39–42% free
by `memory_pressure -Q`, and about 3.2 GiB of swap already used with no VMs.
Parallels 27.1 was installed but listed no VMs, and its GUI was open. These
measurements are from the current operator account and are **not** a clean
test-account baseline. They do not qualify the candidate. Do not copy machine
identifiers, credential state, or raw process listings into public evidence.

On 2026-11-07, the same non-disposable account showed 49% free memory and
about 1.46 GiB of swap in use with no VMs. Parallels 27.1 returned an empty
global JSON inventory while its GUI was open, but `prlctl` could not connect
to its service after the GUI closed. The morning gate therefore remains
unrunnable on this setup until Parallels works with the GUI closed. These
observations do not establish a clean-machine or loaded-VM result.

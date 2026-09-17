# Lessons Learned

A record of real obstacles hit during development, kept because most of
them generalize past this specific project. Grouped by shape, not by
date.

## This machine has less headroom than it looks like it has

Converting the Fedora VM's disk from VMware's format to QEMU's own
(`qemu-img convert`, one 16GB file) got killed for running low on memory
three times in a row, even though the system reported around 11GB
"available" each time. The same thing happened again, separately, three
more times while trying to shrink that same file back down afterward.
Neither is a huge operation on paper; both repeatedly used more real
memory than this 14GB host, already running a browser, a chat client,
and several other sessions, actually had spare. The disk-shrinking
attempt was eventually abandoned rather than keep spending time on it;
the file stayed larger than ideal, correct but not compact.

A related version of the same lesson: a scratch file needed for
inspecting the VM's disk was first placed under `/tmp`, which turned out
to be a 7.5GB RAM-backed filesystem, not real disk space. It failed
silently at the same point, around 6GB in, until moved to a location
backed by the actual disk.

## Small sandbox quirks that cost real time before they were understood

A background process started the ordinary way (`command & disown`) was
found to not survive between separate tool calls in this working
environment, and was silently killed partway through a large copy
without any error. Using the tool's own proper background-task option
instead fixed it for good.

A permission setting that blocks file reads outside the project
directory could not be loosened for this project alone, because "block"
wins over "allow" no matter which configuration file says which. The
actual fix was a different setting entirely, one that extends what
counts as "inside" the project rather than trying to override the block.

A network socket used to control the test VM failed with a cryptic path
length error until moved to a short path; the one first tried, buried
several directories deep, was a few characters over the operating
system's own limit for that kind of address.

And a background watcher process, used to detect when a long-running
command had finished, checked for that command's name using a search
that matched its own command line too, so it never saw the target
process disappear and just ran until it timed out. Twice, before the
pattern was recognized.

## Working around a missing tool instead of installing one

Inspecting the test VM's disk required a tool (`lvm2`) that wasn't
installed on this machine, and installing it needed a password that
wasn't available in this session. Rather than get stuck, the disk's own
volume layout was read directly, by hand, from its plain-text metadata,
which gave the exact location of the data needed without requiring that
tool at all.

## Getting commands into a VM without the usual shortcut

The usual way to run commands inside a VM from outside it, over SSH with
a password, wasn't available (the tool for supplying a password
non-interactively wasn't installed). Typing commands directly into the
VM's own console instead turned out to double as exactly what was
wanted anyway: a visible window to watch. The first version of that
approach mishandled several punctuation characters used in normal shell
commands (semicolons, pipes, redirects, quotes), silently turning one
intended command into several garbled ones, until each was mapped to
its correct name individually.

## Depending on someone else's setup comes with someone else's surprises

Three separate surprises turned up while standing up OpenCTI, each only
visible once actually attempted rather than assumed from documentation:

- The standard image for one required piece (MinIO) stopped being
  pullable without logging in, a policy change on their end. An
  alternate, still-open source for the same image fixed it.
- The reference deployment repository this project's own deployment
  setup was informed by turned out to carry no license file of its own,
  unlike the actual platform's repository. That changed the plan from
  "adapt their file" to "write an original one informed by public
  documentation instead," to stay clearly on the right side of that.
- That same reference deployment bundled an entire second product by
  default, alongside the one actually needed, adding real memory and
  disk cost for a feature nothing in this project's design calls for.
  Caught before anything was ever deployed.

Separately: forking the platform's own repository did not bring its
release tags along, only its branches, so the specific release version
needed had to be fetched from the original project and pushed across
by hand. And the branch that got forked turned out to already be
several commits past the last actual release, unreleased, in-progress
work, so this project's own starting point was reset back to the real
release before building anything on top of it.

That fork was later dropped entirely, once a closer read of the
platform's own license file turned up a second, much more restrictive
license covering a large set of its features, a real distribution risk
this project's own deployment never actually needed to take on, since
it had been pulling the plain public Docker image all along rather
than building from the fork's source. See
[decision-record.md](decision-record.md) for the full reasoning.

## The real error was three layers down from the one on screen

Getting OpenCTI itself to actually stay up took four separate rounds of
diagnosis, each one looking like the real cause until the next layer
underneath it turned out to be the actual problem:

- **What it looked like:** OpenCTI kept exiting cleanly and restarting,
  logging search errors against its own database.
- **First hypothesis, wrong:** looked like Elasticsearch just needed a
  bigger memory allowance than the resource-constrained 1GB it had been
  given. Raised it to 2GB. Elasticsearch itself still wouldn't turn
  healthy, and OpenCTI still wouldn't stay up. Not the real cause.
- **Second layer, the actual root cause:** Elasticsearch's own logs (not
  OpenCTI's) showed a disk watermark warning: its data volume had 620MB
  free out of 15GB, 96% used, triggering a safety mechanism that makes
  every index read-only. The VM's whole disk, not memory, was the
  problem, a `df -h` that should have been checked earlier than it was.
  Fixed properly: grew the virtual disk (30GB more), then grew the
  partition, the LVM volume, and the filesystem on top of it, in that
  order, all while the VM was shut down cleanly first.
- **Third layer, revealed only after the disk was fixed:** OpenCTI now
  refused to start for a completely different reason: a prior failed
  attempt had left a partially created Elasticsearch index behind, and
  OpenCTI correctly refuses to resume an interrupted first-time setup
  rather than guess. Nothing valuable had been stored yet, so the fix
  was to wipe the stack's data volumes and let it initialize once, from
  nothing, cleanly.

None of the individual fixes were wrong to try. Each one was aimed at a
real, correctly diagnosed problem, just not the deepest one yet. The
actual lesson: when a fix doesn't fully resolve the symptom, that's a
signal to look one layer further down, in the failing component's own
logs specifically, rather than retry the same fix harder.

A smaller, separate obstacle from the same stretch of work: growing the
disk partition required answering an interactive tool's prompts with the
exact words it expected (`Fix`, not `Yes`), and one punctuation character
(`%`, needed to say "the rest of the disk") had been left out of the
console-typing script's character map, so the first attempt at typing
`100%` silently became `100`.

## A missing CPU flag looked like a crash in a completely different service

Restarting the local test VM under a fresh QEMU process (after a session
gap) left three containers stuck restarting on a loop: OpenCTI's own
platform container, its `connector-opencti` container, and separately,
MinIO. The first two looked like the actual problem, since OpenCTI was
the thing being tested. MinIO's own logs told the real story: `Fatal
glibc error: CPU does not support x86-64-v2`. The newer MinIO image had
been built expecting a CPU instruction set QEMU's default emulated CPU
model doesn't expose, unrelated to anything about OpenCTI's own
configuration or the VM's disk, network, or memory. Once MinIO couldn't
start, OpenCTI's own startup checks (which depend on object storage
being reachable) failed too, and both looked like they were the
problem.

Fixed by relaunching the VM with `-cpu host`, passing through the real
host CPU's full instruction set to the guest. Every container came up
healthy on the next boot. The lesson matches an earlier one from this same project:
when a fix doesn't fully resolve the symptom, or when the service that's
actually crashing isn't the one that looks broken from the outside, the
real cause is often sitting in a completely different component's own
logs, not the one getting the most attention.

## What's likely still ahead

Noted here so it's not a surprise later, not because any of it is a
problem yet:

- The plan to connect this VM to the original VMware-based test network,
  so the two can be tested together, hasn't been attempted yet and will
  likely have its own connectivity questions once it is.
- How much further this same host can be pushed before something else
  has to move to different hardware, or a different disk, is an open
  question, not a settled one.
- Whether the classifier and peer validation layer, once built, add
  meaningfully to the same VM's resource load is unverified until
  they exist.

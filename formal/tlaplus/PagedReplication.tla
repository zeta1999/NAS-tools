------------------------------ MODULE PagedReplication ------------------------------
(***************************************************************************)
(* Paged push and pull for a backup catalog that does not fit in one       *)
(* control frame. Transcribed from simple-backups                          *)
(* `crates/backups-transfer`: `pages.rs` and `pushpull.rs`.                 *)
(*                                                                         *)
(* The manifest is the canonical JSON, cut into slices of bounded size.    *)
(* `Slices = <<1, 2, 3>>` and `PageBudget = 2`. Slices 1 and 2 are the two *)
(* halves of one file's chunk list; slice 3 is the rest. Object pages hold *)
(* at most `PageBudget` ids. There is no action that sends `Objects` as    *)
(* one message.                                                            *)
(*                                                                         *)
(* A snapshot is committed only when the last slice has been concatenated  *)
(* (`assembled = Slices`, the content hash) and every named object is      *)
(* stored. `RequireCommitGuard` is that check. Switching it off is the     *)
(* negative control: `EarlyCommit` then stores a partial.                  *)
(*                                                                         *)
(* An object page may skip an id only after `Read`, which is the streamed  *)
(* possession proof (`open_object`, not a claim). An old peer cannot       *)
(* decode `PushPaged` / `PullPaged` and the session fails with nothing     *)
(* committed. `Retry` starts another session; stored objects and the reads *)
(* stay, and the page bound still holds.                                   *)
(*                                                                         *)
(* | Model | Rust |                                                         *)
(* |---|---|                                                               *)
(* | `Begin("push")` | `PushPaged` then `SnapshotHead` |                   *)
(* | `Begin("pull")` | `PullPaged` |                                       *)
(* | `Reject` | old decoder drops the paged message |                      *)
(* | `Read(o)` | `possession_digest_reader` over `open_object` |           *)
(* | `ObjectPage` | `ObjectPage` / `WantObjects`; skip iff stored and read | *)
(* | `TakeSlice` | `ManifestBytes` in order; write on `last` only |        *)
(* | `EarlyCommit` | the write with the hash and presence check removed |  *)
(* | `Retry` | run `push` or `pull` again; no write-ahead log |            *)
(*                                                                         *)
(* FastCDC, the job file, and the convergence-secret flag are not this     *)
(* model.                                                                   *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Objects, PageBudget, RequireCommitGuard

\* Three slices. 1 and 2 are the two halves of one file's chunk list.
Slices == <<1, 2, 3>>

VARIABLES
  phase,       \* "init" | "open" | "failed" | "done"
  peer,        \* "none" | "old" | "new"
  direction,   \* "none" | "push" | "pull"
  stored,
  readSet,
  skippedLog,
  assembled,
  committed,
  pages

vars == <<phase, peer, direction, stored, readSet, skippedLog, assembled, committed, pages>>

Init ==
  /\ phase = "init"
  /\ peer = "none"
  /\ direction = "none"
  /\ stored = {}
  /\ readSet = {}
  /\ skippedLog = {}
  /\ assembled = << >>
  /\ committed = FALSE
  /\ pages = {}

Reject ==
  /\ phase = "init"
  /\ peer' = "old"
  /\ phase' = "failed"
  /\ UNCHANGED <<direction, stored, readSet, skippedLog, assembled, committed, pages>>

Begin(dir) ==
  /\ phase = "init"
  /\ peer' = "new"
  /\ direction' = dir
  /\ phase' = "open"
  /\ UNCHANGED <<stored, readSet, skippedLog, assembled, committed, pages>>

Read(o) ==
  /\ phase = "open"
  /\ o \in stored
  /\ readSet' = readSet \cup {o}
  /\ UNCHANGED <<phase, peer, direction, stored, skippedLog, assembled, committed, pages>>

ObjectPage(page) ==
  /\ phase = "open"
  /\ page \subseteq Objects
  /\ page # {}
  /\ Cardinality(page) \leq PageBudget
  /\ LET skipped == { o \in page : o \in stored /\ o \in readSet }
         sent == page \ skipped
     IN /\ stored' = stored \cup sent
        /\ skippedLog' = skippedLog \cup skipped
        /\ pages' = pages \cup {page}
  /\ UNCHANGED <<phase, peer, direction, readSet, assembled, committed>>

TakeSlice ==
  /\ phase = "open"
  /\ Len(assembled) < Len(Slices)
  /\ assembled' = Append(assembled, Slices[Len(assembled) + 1])
  /\ IF Len(assembled') = Len(Slices)
     THEN /\ phase' = "done"
          /\ committed' = IF RequireCommitGuard
                          THEN assembled' = Slices /\ stored = Objects
                          ELSE TRUE
     ELSE UNCHANGED <<phase, committed>>
  /\ UNCHANGED <<peer, direction, stored, readSet, skippedLog, pages>>

\* The commit check removed. A partial concatenation becomes a snapshot.
EarlyCommit ==
  /\ ~RequireCommitGuard
  /\ phase = "open"
  /\ committed' = TRUE
  /\ phase' = "done"
  /\ UNCHANGED <<peer, direction, stored, readSet, skippedLog, assembled, pages>>

Retry ==
  /\ phase \in {"done", "failed"}
  /\ phase' = "init"
  /\ peer' = "none"
  /\ direction' = "none"
  /\ assembled' = << >>
  /\ committed' = FALSE
  /\ UNCHANGED <<stored, readSet, skippedLog, pages>>

Next ==
  \/ Reject
  \/ Begin("push")
  \/ Begin("pull")
  \/ \E o \in Objects : Read(o)
  \/ \E page \in SUBSET Objects : ObjectPage(page)
  \/ TakeSlice
  \/ EarlyCommit
  \/ Retry

Spec == Init /\ [][Next]_vars

\* A committed snapshot is the whole manifest, and every object is stored.
NoPartialCommit ==
  committed => assembled = Slices /\ stored = Objects

\* A skip was a proof over bytes the receiver had read.
SkipImpliesRead ==
  skippedLog \subseteq readSet

\* An undecodable page ends the session with nothing committed.
FailedIsNotCommit ==
  phase = "failed" => ~committed

\* Including after Retry. No control step sends the whole catalog.
PageBound ==
  \A page \in pages : Cardinality(page) \leq PageBudget

=============================================================================

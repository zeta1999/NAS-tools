#!/usr/bin/env bash
. "$(dirname "$0")/lib.sh"
uc_begin UC08 "Several coding agents at once" "SPECS §19.8, §7.4, §7.5" "M5"
check         "git remote helper is discoverable as git-remote-nas" command -v git-remote-nas
check         "clone and push round-trip through nas://"         $NAS test git-roundtrip work
check         "the OID map never leaves the encrypted manifest"  $NAS test git-oidmap-encrypted work
check         "objects are stored inflated, not as packfiles"    $NAS test git-loose-objects work
# Distinct branches are distinct slots, so there is nothing to contend over.
check         "4 worktrees push 4 branches with zero conflicts"  $NAS test git-parallel-worktrees work --agents 4
check         "two agents on ONE branch collide as non-fast-forward" $NAS test git-same-branch-collision work
check         "a linked worktree's .git file is handled"         $NAS test git-worktree-gitfile work
check         "patch export/import round-trips"                  $NAS test patch-roundtrip work
check         "a patch queue is append-only"                     $NAS test patch-queue-append-only work
check_refuses "an unrostered author's patch is refused"          $NAS test patch-unrostered work
uc_summary

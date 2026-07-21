; installer.nsi — NSIS installer for koidra-gateway (Windows).
;
; This is the SOLE migration vehicle for the koidra-ssh -> koidra-gateway rename.
; It is an IDENTITY-PRESERVING UPGRADE installer, run AT CONSOLE by an operator.
;
; ============================ DESIGN (read before editing) ===================
;
; 1. Detect the existing OLD install BY DIRECTORY:
;      admin     -> %PROGRAMDATA%\koidra-ssh   (resolved via ReadEnvStr into the
;                   $ProgramData var, NOT the built-in PROGRAMDATA constant:
;                   nixpkgs NSIS lacks that constant — it warns + ignores, board gotcha)
;      non-admin -> %LOCALAPPDATA%\koidra-ssh
;    Re-run detection is CONTENT-based, not bare dir existence (C1/M4): a
;    koidra-gateway dir with a NON-EMPTY primary.json is a genuine prior install
;    -> "repair"; an absent/0-byte json means a half-failed fresh -> "fresh"
;    (re-key), never a silent-no-op "repair" that locks the box out.
;
; 2. IDENTITY PRESERVATION: COPY primary.json + backup.json BYTE-IDENTICAL from
;    the OLD dir into the new dir. NEVER mint fresh identity on an upgrade. If the
;    old jsons are missing on an upgrade, ABORT (do not silently create identity).
;    The json IS the whole node identity (machine_key/node_key/network_lock_key);
;    a byte copy => same nodeId + same 100.x IP.
;
; 3. AUTH KEY: parse the baked `-k tskey-auth-...` token out of the OLD
;    run-node.cmd (extract-authkey.ps1) and write it to authkey.txt beside the new
;    launcher, which reads it AT LAUNCH from disk. NEVER an env var — SYSTEM-task
;    env is stale until reboot and reboot is a hard NO.
;
; 4. TS_HOSTNAME: the new launcher (run-node2.cmd) sets TS_HOSTNAME=%COMPUTERNAME%-
;    <channel>, replicating the old console name exactly (Windows node name comes
;    from TS_HOSTNAME, not the json) so the console name never churns.
;
; 5. STOP OLD BEFORE START NEW, PER-CHANNEL (H3): stop-old-stack.ps1 <oldDir>
;    <isAdmin> <channel> ends that channel's old KoidraSSH-* task, kills its
;    ssh_shell* + supervise loop, and VERIFIES zero remain, BEFORE that channel's
;    new task is /run. SecStart swaps BACKUP fully, then PRIMARY — the two old
;    channels are never both down at once (>=1 up throughout). Never two processes
;    on one keyfile.
;
; 6. Both channels on port 22 (each channel is its own tailnet IP — no conflict).
;
; 7. TWO-PHASE PERSISTENCE. This run INSTALLS + STARTS the new koidra-gateway
;    persistence but DOES NOT delete the old KoidraSSH-* tasks / KoidraSSH.lnk.
;    The old persistence stays the intact boot fallback until the coordinator's
;    EXTERNAL validation passes. A SEPARATE `/FINALIZE` run removes old
;    persistence (only — never the old dir) after validation.
;
; 8. The old C:\...\koidra-ssh dir is LEFT ON DISK. Directory deletion is the
;    coordinator's later list-before-delete pass, never this installer's job.
;
; 9. Elevation: if an admin (ProgramData) layout is present but the installer is
;    NOT elevated, ABORT — never install a divergent %LOCALAPPDATA% copy with
;    fresh keys next to a live SYSTEM stack.
;
; 10. No built-in PROGRAMDATA constant; no WriteEnvStr (no env writes at all).
;
; 11. /REPROVISION (operator escape hatch, C1): on a net-new/lab box whose fresh
;     install half-failed (bad key + unregistered/0-byte json), force the
;     fresh-provision path — overwrite authkey.txt from the operator key, wipe
;     ONLY 0-byte/unregistered jsons (NEVER a non-empty registered one), rewrite
;     the launcher. Without it, a bad key would be silently kept and run 2 no-ops.
;
; 12. /CONSOLE + over-SSH guard (H3): the UPGRADE path stops the old stack, which
;     over the box's OWN koidra SSH channel would kill the transport mid-run and
;     brick the box. check-console.ps1 refuses to run when launched under an
;     ssh_shell* ancestor (best-effort); /CONSOLE bypasses if the operator is
;     certain it is a console session. Fresh/repair/reprovision are NOT guarded
;     (they never stop an old stack, so an over-SSH lab install is safe).
;
; Build:  makensis -DGW_SHA=<sha> installer.nsi
;   Stage beside this .nsi: koidra_gateway.exe (raw Cargo example output),
;   run-node2.cmd, supervisor.vbs, start-{primary,backup}.vbs,
;   start-{primary,backup}-old.vbs, extract-authkey.ps1, stop-old-stack.ps1,
;   check-console.ps1.
;   For a FRESH (net-new / lab) box, also stage primary.json/backup.json and/or
;   authkey.txt beside the .nsi, or set KOIDRA_PRIMARY_AUTHKEY in the environment.
; =============================================================================

!include "LogicLib.nsh"
!include "MUI2.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"   ; GetParameters / GetOptions
!include "TextFunc.nsh"   ; TrimNewLines (read the pointer file's exe name cleanly)
!include "nsDialogs.nsh"  ; Auth-key prompt dialog (interactive fresh-install UX)

Name "Koidra Gateway"
OutFile "koidra-gateway-setup.exe"
Unicode True
ShowInstDetails show
; Operator must right-click → Run as administrator. We do NOT use RequestExecutionLevel
; admin because auto-elevation via UAC manifest strips the command-line args (/AUTHKEY=)
; and env vars at the elevation boundary — the elevated process doesn't inherit them.
; When the operator manually elevates (right-click → Run as admin), args/env ARE
; preserved. This is the documented NSIS/Windows behavior.
RequestExecutionLevel user

; The staged versioned binary name. Overridable at build time (-DGW_SHA=<sha>).
; This name IS the process image AND the pointer-file content AND what the
; launcher runs — kept consistent kit-wide (no hyphen/underscore split).
!ifndef GW_SHA
    !define GW_SHA "06f9a3a"
!endif
!define BIN_SRC       "koidra_gateway.exe"                 ; raw Cargo example output staged beside the .nsi
!define BIN_VERSIONED "koidra-gateway-${GW_SHA}.exe"       ; installed name = process image = pointer content

VIProductVersion "0.4.0.254"
VIAddVersionKey "ProductName"    "Koidra Gateway"
VIAddVersionKey "FileDescription" "Koidra Gateway setup"
VIAddVersionKey "CompanyName"    "Koidra"
VIAddVersionKey "LegalCopyright" "(c) 2026 Koidra"
VIAddVersionKey "FileVersion"    "0.4.0.254"
VIAddVersionKey "ProductVersion" "0.4.0.254"

Var IsAdmin       ; "1" if the current token is elevated
Var Finalize      ; "1" if launched with /FINALIZE (persistence-removal pass only)
Var StageOnly     ; "1" if launched with /STAGE-ONLY (skip auto-finalize, keep old persistence)
Var Reprovision   ; "1" if launched with /REPROVISION (operator escape hatch: force
                  ;     fresh-provision on an existing net-new/lab koidra-gateway dir)
Var ConsoleAck    ; "1" if launched with /CONSOLE (bypass the best-effort over-SSH guard)
Var ProgramData   ; %PROGRAMDATA%   (via ReadEnvStr)
Var LocalAppDir   ; %LOCALAPPDATA%  (via ReadEnvStr)
Var BaseDir       ; ProgramData (admin) or LocalAppData (non-admin)
Var OldDir        ; <BaseDir>\koidra-ssh
Var Mode          ; "upgrade" | "fresh" | "repair" | "reprovision"
Var AuthKey       ; /AUTHKEY= CLI flag (universal belt-and-suspenders fallback)
Var AuthKeyField  ; nsDialogs text field handle (interactive auth-key prompt)
Var AuthKeyPageShown  ; "1" if the auth-key page was displayed

; Directory is COMPUTED from the detected layout — never operator-chosen (a wrong
; dir loses identity). So no MUI_PAGE_DIRECTORY / COMPONENTS.
!insertmacro MUI_PAGE_WELCOME
Page custom AuthKeyPageCreate AuthKeyPageLeave
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

; --------------------------------------------------------------------------- ;
Function .onInit
    StrCpy $Finalize 0
    StrCpy $Reprovision 0
    StrCpy $ConsoleAck 0
    StrCpy $StageOnly 0
    StrCpy $AuthKey ""
    StrCpy $AuthKeyPageShown "0"

    ${GetParameters} $R0

    ; /AUTHKEY= — operator-supplied auth key (belt-and-suspenders fallback for ALL
    ; modes). Written to authkey.txt if no existing non-empty key is found.
    ClearErrors
    ${GetOptions} $R0 "/AUTHKEY=" $R1
    ${IfNot} ${Errors}
    ${AndIf} $R1 != ""
        StrCpy $AuthKey $R1
    ${EndIf}

    ; /FINALIZE — persistence-removal pass only (§7). No install, no identity, no
    ; new tasks; just remove the OLD persistence after external validation.
    ClearErrors
    ${GetOptions} $R0 "/FINALIZE" $R1
    ${IfNot} ${Errors}
        StrCpy $Finalize 1
    ${EndIf}

    ; /STAGE-ONLY — skip auto-finalize. The installer stages + starts new
    ; channels but does NOT remove old persistence (the old two-phase pattern).
    ; Useful for automated fleet rolls that want external verify-first.
    ClearErrors
    ${GetOptions} $R0 "/STAGE-ONLY" $R1
    ${IfNot} ${Errors}
        StrCpy $StageOnly 1
    ${EndIf}

    ; /REPROVISION — operator escape hatch (§11). Forces the fresh-provision path
    ; on an existing net-new/lab koidra-gateway dir: re-key from the operator's key
    ; and wipe any 0-byte/unregistered json so the binary re-inits. Ignored when an
    ; old koidra-ssh dir is present (that is an identity-preserving UPGRADE).
    ClearErrors
    ${GetOptions} $R0 "/REPROVISION" $R1
    ${IfNot} ${Errors}
        StrCpy $Reprovision 1
    ${EndIf}

    ; /CONSOLE — assert this run is at the physical/RDP console, bypassing the
    ; best-effort over-SSH guard (§12) in case its parent-process detection
    ; false-positives. Use ONLY when you are truly at the console.
    ClearErrors
    ${GetOptions} $R0 "/CONSOLE" $R1
    ${IfNot} ${Errors}
        StrCpy $ConsoleAck 1
    ${EndIf}

    ; Elevation.
    UserInfo::GetAccountType
    Pop $0
    ${If} $0 == "Admin"
        StrCpy $IsAdmin 1
    ${Else}
        StrCpy $IsAdmin 0
    ${EndIf}

    ; Environment dirs (NOT the built-in PROGRAMDATA constant — absent in nixpkgs NSIS).
    ReadEnvStr $ProgramData  "PROGRAMDATA"
    ReadEnvStr $LocalAppDir "LOCALAPPDATA"

    ${If} $Finalize == 1
        Call DoFinalize
        Quit
    ${EndIf}

    ; ---- Layout detection (by DIRECTORY) --------------------------------- ;
    ${If} ${FileExists} "$ProgramData\koidra-ssh\*.*"
        ; Admin layout present.
        ${If} $IsAdmin != 1
            DetailPrint "ABORT: admin (ProgramData) koidra-ssh install present but installer not elevated — re-run as Administrator."
            SetErrorLevel 2
            ${IfNot} ${Silent}
                MessageBox MB_OK|MB_ICONSTOP "An admin (ProgramData) koidra-ssh install is present at $ProgramData\koidra-ssh, but this installer is NOT running elevated.$\n$\nRe-run koidra-gateway-setup.exe as Administrator. Refusing to install a divergent per-user copy with fresh keys next to the live SYSTEM stack."
            ${EndIf}
            Abort
        ${EndIf}
        StrCpy $BaseDir $ProgramData
        StrCpy $Mode "upgrade"
    ${ElseIf} ${FileExists} "$LocalAppDir\koidra-ssh\*.*"
        ; Non-admin layout present.
        StrCpy $BaseDir $LocalAppDir
        StrCpy $Mode "upgrade"
    ${Else}
        ; No old koidra-ssh dir -> fresh install (net-new box / Azure lab).
        ${If} $IsAdmin == 1
            StrCpy $BaseDir $ProgramData
        ${Else}
            StrCpy $BaseDir $LocalAppDir
        ${EndIf}
        StrCpy $Mode "fresh"

        ; ---- C1/M4: CONTENT-based re-run detection (NOT bare dir existence) --- ;
        ; A half-failed FRESH install can leave a koidra-gateway dir + a bad
        ; authkey.txt + a self-created UNREGISTERED / 0-byte json. Bare dir
        ; existence -> "repair" would then silently preserve those artifacts and
        ; no-op run 2, locking the box out (the confirmed field incident).
        ;
        ; A GENUINE prior install has a NON-EMPTY primary.json (the binary writes
        ; real state once it registers). So:
        ;   * /REPROVISION            -> force fresh-provision (re-key, wipe stubs)
        ;   * non-empty primary.json  -> genuine prior state -> "repair"
        ;   * absent / 0-byte json    -> NEVER-provisioned  -> "fresh" (re-key)
        ${If} $Reprovision == 1
            StrCpy $Mode "reprovision"
        ${ElseIf} ${FileExists} "$BaseDir\koidra-gateway\primary.json"
            ClearErrors
            FileOpen $4 "$BaseDir\koidra-gateway\primary.json" r
            ${IfNot} ${Errors}
                FileSeek $4 0 END $5      ; $5 = file size in bytes
                FileClose $4
                ${If} $5 > 0
                    StrCpy $Mode "repair"     ; registered identity present
                ${Else}
                    StrCpy $Mode "fresh"      ; 0-byte stub -> never provisioned
                ${EndIf}
            ${Else}
                StrCpy $Mode "fresh"          ; unreadable -> treat as never provisioned
            ${EndIf}
        ${EndIf}
        ; (a koidra-gateway dir with NO primary.json at all stays "fresh")
    ${EndIf}

    StrCpy $OldDir  "$BaseDir\koidra-ssh"
    StrCpy $INSTDIR "$BaseDir\koidra-gateway"

    ; Per-user vs machine-wide shell folders (Startup shortcut target).
    ${If} $IsAdmin == 1
        SetShellVarContext all
    ${Else}
        SetShellVarContext current
    ${EndIf}
FunctionEnd

; --------------------------------------------------------------------------- ;
; Auth-key prompt page (interactive fresh/repair mode).
Function AuthKeyPageCreate
    StrCpy $AuthKeyPageShown "0"
    ${If} $Mode == "upgrade"
        Abort
    ${EndIf}
    ${If} $AuthKey != ""
        Abort
    ${EndIf}
    ${If} $Mode == "repair"
    ${AndIf} ${FileExists} "$INSTDIR\authkey.txt"
        ClearErrors
        FileOpen $0 "$INSTDIR\authkey.txt" r
        ${IfNot} ${Errors}
            FileSeek $0 0 END $1
            FileClose $0
            ${If} $1 > 0
                Abort
            ${EndIf}
        ${EndIf}
    ${EndIf}
    nsDialogs::Create 1018
    Pop $0
    ${If} $0 == error
        Abort
    ${EndIf}
    ${NSD_CreateLabel} 0 0 100% 36u "Tailscale provisioning auth key for this box.$\r$\nMint one from the Tailscale admin console (Settings -> Keys), or use the per-box key from the cheat-sheet."
    Pop $0
    ${NSD_CreateText} 0 40u 100% 12u ""
    Pop $AuthKeyField
    StrCpy $AuthKeyPageShown "1"
    nsDialogs::Show
FunctionEnd

Function AuthKeyPageLeave
    ${If} $AuthKeyPageShown == "1"
        ${NSD_GetText} $AuthKeyField $AuthKey
    ${EndIf}
    ${If} $AuthKey == ""
        MessageBox MB_ICONEXCLAMATION "A Tailscale auth key is required. Enter one or re-run with /AUTHKEY=<key>."
        Abort
    ${EndIf}
    StrCpy $0 $AuthKey 11
    ${If} $0 != "tskey-auth-"
        MessageBox MB_ICONEXCLAMATION "The auth key should start with 'tskey-auth-'. Please check the key and re-enter."
        Abort
    ${EndIf}
FunctionEnd

; --------------------------------------------------------------------------- ;
; /FINALIZE: remove ONLY the old persistence (tasks / Startup .lnk). Never the
; old dir (§8 — that is the coordinator's list-before-delete pass).
Function DoFinalize
    DetailPrint "FINALIZE: removing old koidra-ssh persistence (dir left on disk)."
    nsExec::ExecToLog 'schtasks /delete /tn "KoidraSSH-primary" /f'
    Pop $0
    nsExec::ExecToLog 'schtasks /delete /tn "KoidraSSH-backup" /f'
    Pop $0
    ; Non-admin Startup shortcut (both contexts, harmless if absent).
    SetShellVarContext current
    Delete "$SMSTARTUP\KoidraSSH.lnk"
    SetShellVarContext all
    Delete "$SMSTARTUP\KoidraSSH.lnk"
    DetailPrint "FINALIZE done. Old $ProgramData\koidra-ssh / $LocalAppDir\koidra-ssh dir NOT deleted (coordinator cleanup pass)."
    DetailPrint "Finalize complete: old KoidraSSH-* tasks and KoidraSSH.lnk removed; old koidra-ssh dir left on disk."
    ${IfNot} ${Silent}
        MessageBox MB_OK "Finalize complete: old KoidraSSH-* tasks and KoidraSSH.lnk removed. The old koidra-ssh directory is left on disk for the coordinator's list-before-delete pass."
    ${EndIf}
FunctionEnd

; --------------------------------------------------------------------------- ;
; REPROVISION helpers (C1): delete an INSTDIR json ONLY when it is 0-byte (an
; unregistered stub) so the binary re-inits. A NON-empty json is a registered
; identity and is NEVER touched. Two near-identical fns because NSIS Function
; params via the stack are noisier than this for a two-call site.
Function WipeStubJson_Primary
    ${If} ${FileExists} "$INSTDIR\primary.json"
        ClearErrors
        FileOpen $6 "$INSTDIR\primary.json" r
        ${IfNot} ${Errors}
            FileSeek $6 0 END $7
            FileClose $6
            ${If} $7 <= 0
                Delete "$INSTDIR\primary.json"
                DetailPrint "REPROVISION: deleted 0-byte primary.json (unregistered stub) so the binary re-inits."
            ${Else}
                DetailPrint "REPROVISION: kept NON-empty primary.json ($7 bytes) — registered identity preserved."
            ${EndIf}
        ${EndIf}
    ${EndIf}
FunctionEnd

Function WipeStubJson_Backup
    ${If} ${FileExists} "$INSTDIR\backup.json"
        ClearErrors
        FileOpen $6 "$INSTDIR\backup.json" r
        ${IfNot} ${Errors}
            FileSeek $6 0 END $7
            FileClose $6
            ${If} $7 <= 0
                Delete "$INSTDIR\backup.json"
                DetailPrint "REPROVISION: deleted 0-byte backup.json (unregistered stub) so the binary re-inits."
            ${Else}
                DetailPrint "REPROVISION: kept NON-empty backup.json ($7 bytes) — registered identity preserved."
            ${EndIf}
        ${EndIf}
    ${EndIf}
FunctionEnd

; --------------------------------------------------------------------------- ;
Section "Koidra Gateway (required)" SecCore
    SectionIn RO
    DetailPrint "Mode: $Mode   Layout base: $BaseDir   Elevated: $IsAdmin"
    SetOutPath "$INSTDIR"

    ; Core files (scripts + helpers). File the raw binary under the VERSIONED name
    ; so the process image, the pointer, and what the launcher runs all match.
    File "run-node2.cmd"
    File "supervisor.vbs"
    File "start-primary.vbs"
    File "start-backup.vbs"
    File "start-primary-old.vbs"
    File "start-backup-old.vbs"
    File "extract-authkey.ps1"
    File "stop-old-stack.ps1"
    File "check-console.ps1"

    ; ---- BINARY STAGING — rename-and-replace (Issue #5) ------------------ ;
    ; RCA (knodt 30h freeze): the OLD installer extracted the binary directly
    ; to the versioned name via `File /oname=...`. When the SAME version is
    ; reinstalled while the process is running, NSIS `File` opens the target
    ; with GENERIC_WRITE — which FAILS on a locked running .exe. Worse, the
    ; cmd-based `copy /Y` variant in the legacy installer would hang on the
    ; locked file indefinitely while the watchdog relaunch cycle recreated
    ; the process in the gap between kill and copy.
    ;
    ; Fix: extract to a `.tmp` side-car, then rename-and-replace. On Windows
    ; NTFS you CAN rename a running .exe (the process holds a file handle, not
    ; a name pin); you just cannot overwrite one. So:
    ;   1. Extract new binary as ${BIN_VERSIONED}.tmp (always safe — new file).
    ;   2. Clear any stale ${BIN_VERSIONED}.old from a prior install.
    ;   3. If the running ${BIN_VERSIONED} exists, rename it aside to .old
    ;      (succeeds even while the process runs — Windows allows renaming a
    ;      locked image).
    ;   4. Rename .tmp → ${BIN_VERSIONED} (target is now free).
    ;   5. Best-effort delete .old (will fail if old process still holds it;
    ;      that's fine — it'll be cleaned up on next install or reboot).
    ; The ~0-ms window between steps 3 and 4 is covered by the launcher's
    ; 5s watchdog loop: if it hits the gap, it logs + retries next cycle.
    File /oname=${BIN_VERSIONED}.tmp "${BIN_SRC}"
    Delete "$INSTDIR\${BIN_VERSIONED}.old"
    ${If} ${FileExists} "$INSTDIR\${BIN_VERSIONED}"
        Rename "$INSTDIR\${BIN_VERSIONED}" "$INSTDIR\${BIN_VERSIONED}.old"
    ${EndIf}
    Rename "$INSTDIR\${BIN_VERSIONED}.tmp" "$INSTDIR\${BIN_VERSIONED}"
    Delete "$INSTDIR\${BIN_VERSIONED}.old"

    ; ---- OVER-SSH GUARD (§12, H3b) — upgrade only ------------------------ ;
    ; Only the UPGRADE path stops a live old stack (stop-old-stack), so only it
    ; can kill the box's own koidra SSH transport mid-run and brick it. Best-effort
    ; parent-process check: refuse if launched under an ssh_shell* ancestor unless
    ; the operator asserted /CONSOLE. (Fresh/repair/reprovision never stop an old
    ; stack, so a lab install driven over SSH is safe and NOT guarded.) The abort
    ; here happens BEFORE any stop, so a false-positive costs nothing.
    ${If} $Mode == "upgrade"
    ${AndIf} $ConsoleAck != 1
        nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\check-console.ps1"'
        Pop $0
        ${If} $0 != 0
            DetailPrint "CONSOLE-ONLY ABORT: over-SSH run detected (ssh_shell* ancestor) — run at console or re-run with /CONSOLE."
            SetErrorLevel 2
            ${IfNot} ${Silent}
                MessageBox MB_OK|MB_ICONSTOP "CONSOLE-ONLY ABORT: this installer appears to be running over the box's own koidra SSH channel (an ssh_shell* ancestor was detected). The upgrade stops the old stack, which would kill this transport mid-run and brick the box (no reboot allowed).$\n$\nRun it AT THE CONSOLE (physical / RDP). If you are certain this is a console session and the detection is wrong, re-run with /CONSOLE."
            ${EndIf}
            Abort
        ${EndIf}
        DetailPrint "Console guard: no ssh_shell* ancestor detected (not an over-SSH run)."
    ${EndIf}

    ; Seed the AUTHORITATIVE version pointer with the versioned binary name (never
    ; a bare unversioned name). The launcher reads this first; the in-process
    ; updater rewrites it (temp+rename). Write temp+rename here too so the
    ; launcher never sees a truncated pointer during the ~0-ms write window.
    FileOpen $0 "$INSTDIR\current-koidra-gateway.txt.tmp" w
    FileWrite $0 "${BIN_VERSIONED}"
    FileClose $0
    Delete "$INSTDIR\current-koidra-gateway.txt"
    Rename "$INSTDIR\current-koidra-gateway.txt.tmp" "$INSTDIR\current-koidra-gateway.txt"

    ; M2: bake the DEFAULT pointer from GW_SHA (the sha this installer actually
    ; bundled). The updater NEVER rewrites this file, so it survives an emptied /
    ; half-written current pointer and keeps the launcher off the hardcoded literal
    ; fallback — the fallback is now a true last resort (both pointers missing).
    FileOpen $0 "$INSTDIR\default-koidra-gateway.txt.tmp" w
    FileWrite $0 "${BIN_VERSIONED}"
    FileClose $0
    Delete "$INSTDIR\default-koidra-gateway.txt"
    Rename "$INSTDIR\default-koidra-gateway.txt.tmp" "$INSTDIR\default-koidra-gateway.txt"

    ; Record the old dir so the rollback launchers (start-*-old.vbs) can find it.
    FileOpen $0 "$INSTDIR\old-install-dir.txt" w
    FileWrite $0 "$OldDir"
    FileClose $0

    ; ---- IDENTITY (§2) --------------------------------------------------- ;
    ${If} $Mode == "upgrade"
        ${IfNot} ${FileExists} "$OldDir\primary.json"
            DetailPrint "UPGRADE ABORT: $OldDir\primary.json is missing — refusing to mint a fresh node identity."
            SetErrorLevel 2
            ${IfNot} ${Silent}
                MessageBox MB_OK|MB_ICONSTOP "UPGRADE ABORT: $OldDir\primary.json is missing. Refusing to mint a fresh node identity. Stage the box's real identity json or investigate before proceeding."
            ${EndIf}
            Abort
        ${EndIf}
        ${IfNot} ${FileExists} "$OldDir\backup.json"
            DetailPrint "UPGRADE ABORT: $OldDir\backup.json is missing — refusing to mint a fresh node identity."
            SetErrorLevel 2
            ${IfNot} ${Silent}
                MessageBox MB_OK|MB_ICONSTOP "UPGRADE ABORT: $OldDir\backup.json is missing. Refusing to mint a fresh node identity."
            ${EndIf}
            Abort
        ${EndIf}
        ; M1: existence is NOT enough — a 0-byte / truncated old json passes
        ; FileExists and would be copied byte-identical, reproducing the
        ; EOF-while-parsing crash-loop on the new layout. A 0-byte identity file
        ; means the box was ALREADY broken; refuse rather than propagate.
        ClearErrors
        FileOpen $6 "$OldDir\primary.json" r
        ${IfNot} ${Errors}
            FileSeek $6 0 END $7
            FileClose $6
        ${Else}
            StrCpy $7 0
        ${EndIf}
        ${If} $7 <= 0
            DetailPrint "UPGRADE ABORT: $OldDir\primary.json is 0-byte / unreadable (corrupt identity) — refusing to copy it onto the new layout."
            SetErrorLevel 2
            ${IfNot} ${Silent}
                MessageBox MB_OK|MB_ICONSTOP "UPGRADE ABORT: $OldDir\primary.json is 0-byte / unreadable (a corrupt identity file). The box is already broken; refusing to copy it onto the new layout. Investigate + restore a good json before proceeding."
            ${EndIf}
            Abort
        ${EndIf}
        ClearErrors
        FileOpen $6 "$OldDir\backup.json" r
        ${IfNot} ${Errors}
            FileSeek $6 0 END $7
            FileClose $6
        ${Else}
            StrCpy $7 0
        ${EndIf}
        ${If} $7 <= 0
            DetailPrint "UPGRADE ABORT: $OldDir\backup.json is 0-byte / unreadable (corrupt identity) — refusing to propagate a broken identity."
            SetErrorLevel 2
            ${IfNot} ${Silent}
                MessageBox MB_OK|MB_ICONSTOP "UPGRADE ABORT: $OldDir\backup.json is 0-byte / unreadable (a corrupt identity file). Refusing to propagate a broken identity onto the new layout."
            ${EndIf}
            Abort
        ${EndIf}
        ; Byte-identical copy -> same nodeId + same 100.x IP.
        CopyFiles /SILENT "$OldDir\primary.json" "$INSTDIR\primary.json"
        CopyFiles /SILENT "$OldDir\backup.json"  "$INSTDIR\backup.json"
        DetailPrint "Identity: copied primary.json + backup.json from $OldDir (byte-identical, non-empty)."
    ${ElseIf} $Mode == "reprovision"
        ; C1 escape hatch: wipe ONLY 0-byte / unregistered stubs so the binary
        ; re-inits on first launch. NEVER delete a NON-empty (registered) json —
        ; that would destroy a real identity (100.x IP + node/machine keys).
        Call WipeStubJson_Primary
        Call WipeStubJson_Backup
        ; After wiping stubs, stage operator identity if present; otherwise the
        ; binary registers on first launch with the (re-keyed) auth key.
        ${IfNot} ${FileExists} "$INSTDIR\primary.json"
            ${If} ${FileExists} "$EXEDIR\primary.json"
                CopyFiles /SILENT "$EXEDIR\primary.json" "$INSTDIR\primary.json"
            ${EndIf}
        ${EndIf}
        ${IfNot} ${FileExists} "$INSTDIR\backup.json"
            ${If} ${FileExists} "$EXEDIR\backup.json"
                CopyFiles /SILENT "$EXEDIR\backup.json" "$INSTDIR\backup.json"
            ${EndIf}
        ${EndIf}
        DetailPrint "Identity: REPROVISION — wiped 0-byte stubs (registered jsons preserved); binary re-inits if none."
    ${ElseIf} $Mode == "repair"
        ; Keep the already-present new jsons; only re-stage if genuinely absent.
        ${IfNot} ${FileExists} "$INSTDIR\primary.json"
            ${If} ${FileExists} "$EXEDIR\primary.json"
                CopyFiles /SILENT "$EXEDIR\primary.json" "$INSTDIR\primary.json"
            ${Else}
                DetailPrint "REPAIR ABORT: $INSTDIR\primary.json missing and no staged copy beside the installer."
                SetErrorLevel 2
                ${IfNot} ${Silent}
                    MessageBox MB_OK|MB_ICONSTOP "REPAIR ABORT: $INSTDIR\primary.json missing and no staged copy beside the installer."
                ${EndIf}
                Abort
            ${EndIf}
        ${EndIf}
        ${IfNot} ${FileExists} "$INSTDIR\backup.json"
            ${If} ${FileExists} "$EXEDIR\backup.json"
                CopyFiles /SILENT "$EXEDIR\backup.json" "$INSTDIR\backup.json"
            ${Else}
                DetailPrint "REPAIR ABORT: $INSTDIR\backup.json missing and no staged copy beside the installer."
                SetErrorLevel 2
                ${IfNot} ${Silent}
                    MessageBox MB_OK|MB_ICONSTOP "REPAIR ABORT: $INSTDIR\backup.json missing and no staged copy beside the installer."
                ${EndIf}
                Abort
            ${EndIf}
        ${EndIf}
        DetailPrint "Identity: repair — kept existing new-dir jsons."
    ${Else}
        ; FRESH (net-new / lab). Use operator-staged identity if present; otherwise
        ; the binary registers a NEW node on first launch via the auth key. Fresh
        ; identity is allowed ONLY here (no koidra-ssh dir exists to preserve).
        ${If} ${FileExists} "$EXEDIR\primary.json"
            CopyFiles /SILENT "$EXEDIR\primary.json" "$INSTDIR\primary.json"
        ${EndIf}
        ${If} ${FileExists} "$EXEDIR\backup.json"
            CopyFiles /SILENT "$EXEDIR\backup.json" "$INSTDIR\backup.json"
        ${EndIf}
        DetailPrint "Identity: FRESH install — first launch registers a new node (no old identity to preserve)."
    ${EndIf}

    ; ---- AUTH KEY (§3) --------------------------------------------------- ;
    ${If} $Mode == "upgrade"
        ; Extract the baked -k token from the old launcher into authkey.txt.
        nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\extract-authkey.ps1" "$OldDir" "$INSTDIR\authkey.txt"'
        Pop $0
        ${If} $0 != 0
            DetailPrint "UPGRADE ABORT: could not extract the baked -k tskey-... auth key from $OldDir\run-node.cmd (exit $0)."
            SetErrorLevel 2
            ${IfNot} ${Silent}
                MessageBox MB_OK|MB_ICONSTOP "UPGRADE ABORT: could not extract the baked -k tskey-... auth key from $OldDir\run-node.cmd (exit $0). Refusing to ship an empty key."
            ${EndIf}
            Abort
        ${EndIf}
        ${IfNot} ${FileExists} "$INSTDIR\authkey.txt"
            DetailPrint "UPGRADE ABORT: authkey.txt was not produced from $OldDir."
            SetErrorLevel 2
            ${IfNot} ${Silent}
                MessageBox MB_OK|MB_ICONSTOP "UPGRADE ABORT: authkey.txt was not produced from $OldDir."
            ${EndIf}
            Abort
        ${EndIf}
        DetailPrint "Auth key: extracted baked token from $OldDir -> authkey.txt."
    ${ElseIf} $Mode == "reprovision"
        ; C1 escape hatch: ALWAYS overwrite authkey.txt from the operator's key
        ; (the whole point — the lockout was a bad key being kept). Prefer a staged
        ; file, else KOIDRA_PRIMARY_AUTHKEY.
        ${If} ${FileExists} "$EXEDIR\authkey.txt"
            CopyFiles /SILENT "$EXEDIR\authkey.txt" "$INSTDIR\authkey.txt"
        ${Else}
            ReadEnvStr $2 "KOIDRA_PRIMARY_AUTHKEY"
            ${If} $2 == ""
                DetailPrint "REPROVISION ABORT: no auth key supplied — stage authkey.txt or set KOIDRA_PRIMARY_AUTHKEY."
                SetErrorLevel 2
                ${IfNot} ${Silent}
                    MessageBox MB_OK|MB_ICONSTOP "REPROVISION ABORT: no auth key supplied. Stage authkey.txt beside the installer or set KOIDRA_PRIMARY_AUTHKEY before re-running with /REPROVISION."
                ${EndIf}
                Abort
            ${EndIf}
            FileOpen $3 "$INSTDIR\authkey.txt" w
            FileWrite $3 "$2"
            FileClose $3
        ${EndIf}
        DetailPrint "Auth key: REPROVISION overwrote authkey.txt from the operator key."
    ${Else}
        ; FRESH / REPAIR — bake the operator-supplied key TO DISK at install time
        ; (reading env NOW to write a file is fine; only LAUNCH-time env is banned).
        ; C1: an EMPTY authkey.txt is treated as ABSENT (a half-failed prior run can
        ; leave a 0-byte key). Only a NON-empty existing key is preserved as-is.
        StrCpy $6 0    ; $6 = 1 when a usable (non-empty) key is already present
        ${If} ${FileExists} "$INSTDIR\authkey.txt"
            ClearErrors
            FileOpen $4 "$INSTDIR\authkey.txt" r
            ${IfNot} ${Errors}
                FileSeek $4 0 END $5
                FileClose $4
                ${If} $5 > 0
                    StrCpy $6 1
                ${EndIf}
            ${EndIf}
        ${EndIf}
        ${If} $6 == 0
            ; /AUTHKEY= CLI flag takes priority (belt-and-suspenders).
            ${If} $AuthKey != ""
                FileOpen $3 "$INSTDIR\authkey.txt" w
                FileWrite $3 "$AuthKey"
                FileClose $3
                DetailPrint "Auth key: baked from /AUTHKEY= CLI flag (fresh/repair)."
            ${ElseIf} ${FileExists} "$EXEDIR\authkey.txt"
                CopyFiles /SILENT "$EXEDIR\authkey.txt" "$INSTDIR\authkey.txt"
            ${Else}
                ReadEnvStr $2 "KOIDRA_PRIMARY_AUTHKEY"
                ${If} $2 == ""
                    DetailPrint "ABORT: no auth key for a fresh install (authkey.txt absent or empty) — stage authkey.txt or set KOIDRA_PRIMARY_AUTHKEY."
                    SetErrorLevel 2
                    ${IfNot} ${Silent}
                        MessageBox MB_OK|MB_ICONSTOP "ABORT: no auth key for a fresh install (existing authkey.txt is absent or empty). Stage authkey.txt beside the installer or set KOIDRA_PRIMARY_AUTHKEY before running."
                    ${EndIf}
                    Abort
                ${EndIf}
                FileOpen $3 "$INSTDIR\authkey.txt" w
                FileWrite $3 "$2"
                FileClose $3
            ${EndIf}
            DetailPrint "Auth key: (re)baked to authkey.txt (fresh/repair; prior key absent or empty)."
        ${Else}
            DetailPrint "Auth key: kept existing non-empty authkey.txt (fresh/repair)."
        ${EndIf}
    ${EndIf}

    ; NOTE (§5, H3): stopping the old stack is NO LONGER done here as a both-channel
    ; step. It is sequenced PER-CHANNEL in SecStart (backup fully stopped+started,
    ; then primary) so both channels are never simultaneously down during an
    ; upgrade. Staging above is non-destructive (copies into the NEW dir beside the
    ; old), so the old stack stays fully up until each channel's swap in SecStart.

    WriteUninstaller "$INSTDIR\uninstall-koidra-gateway.exe"
SectionEnd

; --------------------------------------------------------------------------- ;
; H3: on UPGRADE, swap PER-CHANNEL (backup fully, then primary) so the two old
; channels are never both down at once — >=1 channel is up at every instant.
; stop-old-stack.ps1 takes a channel arg and only stops/verifies that channel.
; On FRESH/REPAIR/REPROVISION there is no old stack, so both channels start
; together.
Section "Start koidra-gateway channels" SecStart
    ${If} $IsAdmin == 1
        ; SYSTEM tasks, onstart, HIGHEST. Both channels on port 22 (§6).
        ; run-node2.cmd self-loops (H1), so the foreground `cmd /c` task recovers
        ; from a binary exit without a reboot. /tr has NO nested quotes (board
        ; gotcha): ProgramData path has no spaces, so the whole `cmd /c <path>
        ; <chan> 22` is a single outer-quoted value.
        nsExec::ExecToLog 'schtasks /create /tn "KoidraGateway-primary" /ru SYSTEM /sc onstart /rl HIGHEST /tr "cmd /c $INSTDIR\run-node2.cmd primary 22" /f'
        Pop $0
        nsExec::ExecToLog 'schtasks /create /tn "KoidraGateway-backup" /ru SYSTEM /sc onstart /rl HIGHEST /tr "cmd /c $INSTDIR\run-node2.cmd backup 22" /f'
        Pop $0

        ; Remove any non-admin Startup .lnk (it competes with the SYSTEM tasks —
        ; both would launch gateway processes, causing identity/port conflicts).
        ; Covers both all-users and current-user Startup folders.
        SetShellVarContext all
        Delete "$SMSTARTUP\KoidraGateway.lnk"
        Delete "$SMSTARTUP\KoidraSSH.lnk"
        SetShellVarContext current
        Delete "$SMSTARTUP\KoidraGateway.lnk"
        Delete "$SMSTARTUP\KoidraSSH.lnk"

        ${If} $Mode == "upgrade"
            ; --- BACKUP channel: stop old backup, then start new backup --------
            DetailPrint "Upgrade: stopping OLD backup channel (primary still serving)..."
            nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\stop-old-stack.ps1" "$OldDir" "$IsAdmin" backup'
            Pop $0
            ${If} $0 != 0
                DetailPrint "ABORT: old BACKUP ssh_shell processes still running after stop (exit $0) — old PRIMARY untouched, box reachable."
                SetErrorLevel 2
                ${IfNot} ${Silent}
                    MessageBox MB_OK|MB_ICONSTOP "ABORT: old BACKUP ssh_shell processes still running after the stop attempt (exit $0). Refusing to start the new backup over a live old one (two processes on one keyfile = orphan node). Old PRIMARY was NOT touched — the box is still reachable. Resolve at console, then re-run."
                ${EndIf}
                Abort
            ${EndIf}
            nsExec::ExecToLog 'schtasks /run /tn "KoidraGateway-backup"'
            Pop $0
            DetailPrint "Admin: new BACKUP started; OLD primary still up (>=1 channel up)."

            ; --- PRIMARY channel: stop old primary, then start new primary -----
            DetailPrint "Upgrade: stopping OLD primary channel (new backup now serving)..."
            nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\stop-old-stack.ps1" "$OldDir" "$IsAdmin" primary'
            Pop $0
            ${If} $0 != 0
                DetailPrint "ABORT: old PRIMARY ssh_shell processes still running after stop (exit $0) — new BACKUP up, box reachable."
                SetErrorLevel 2
                ${IfNot} ${Silent}
                    MessageBox MB_OK|MB_ICONSTOP "ABORT: old PRIMARY ssh_shell processes still running after the stop attempt (exit $0). New BACKUP is up (box reachable); refusing to start the new primary over a live old one. Resolve at console, then re-run."
                ${EndIf}
                Abort
            ${EndIf}
            nsExec::ExecToLog 'schtasks /run /tn "KoidraGateway-primary"'
            Pop $0
            DetailPrint "Admin: new PRIMARY started; both channels now on koidra-gateway."
        ${Else}
            ; Fresh / repair / reprovision — start both.
            ; Repair mode fix: old gateway processes may still be running (the
            ; "no old stack" assumption was wrong for repair — the box has an
            ; existing koidra-gateway install with live processes). Kill them
            ; before starting new ones, otherwise port/identity conflict causes
            ; the new processes to crash silently.
            FileOpen $R8 "$INSTDIR\kill-old-gw.cmd" w
            FileWrite $R8 '@echo off$\r$\n'
            FileWrite $R8 'taskkill /f /im koidra-gateway-*.exe 2>nul$\r$\n'
            FileClose $R8
            nsExec::ExecToLog '"$INSTDIR\kill-old-gw.cmd"'
            Delete "$INSTDIR\kill-old-gw.cmd"
            nsExec::ExecToLog 'schtasks /run /tn "KoidraGateway-backup"'
            Pop $0
            nsExec::ExecToLog 'schtasks /run /tn "KoidraGateway-primary"'
            Pop $0
            DetailPrint "Admin: KoidraGateway-primary/-backup created (onstart) and started."
        ${EndIf}
    ${Else}
        ; Non-admin: ONE Startup shortcut -> supervisor.vbs (MASTER) which spawns
        ; BOTH self-looping run-node2.cmd channels at boot (symmetric bring-up, no
        ; per-channel onlogon task, no primary double-launch). Matches the old
        ; KoidraSSH.lnk contract.
        CreateShortcut "$SMSTARTUP\KoidraGateway.lnk" "$SYSDIR\wscript.exe" '"$INSTDIR\supervisor.vbs"' "$INSTDIR\${BIN_VERSIONED}" 0

        ${If} $Mode == "upgrade"
            ; Per-channel swap for THIS run (boot persistence via the .lnk above).
            ; start-<chan>.vbs detaches a self-looping run-node2.cmd (SSH-safe).
            DetailPrint "Upgrade: stopping OLD backup channel (primary still serving)..."
            nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\stop-old-stack.ps1" "$OldDir" "$IsAdmin" backup'
            Pop $0
            ${If} $0 != 0
                DetailPrint "ABORT: old BACKUP loop/processes still running after stop (exit $0) — old PRIMARY untouched, box reachable."
                SetErrorLevel 2
                ${IfNot} ${Silent}
                    MessageBox MB_OK|MB_ICONSTOP "ABORT: old BACKUP loop/processes still running after the stop attempt (exit $0). Old PRIMARY was NOT touched (box reachable). Resolve at console, then re-run."
                ${EndIf}
                Abort
            ${EndIf}
            Exec '"$SYSDIR\wscript.exe" "$INSTDIR\start-backup.vbs"'
            DetailPrint "Non-admin: new BACKUP started detached; OLD primary still up."

            DetailPrint "Upgrade: stopping OLD primary channel (new backup now serving)..."
            nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\stop-old-stack.ps1" "$OldDir" "$IsAdmin" primary'
            Pop $0
            ${If} $0 != 0
                DetailPrint "ABORT: old PRIMARY loop/processes still running after stop (exit $0) — new BACKUP up, box reachable."
                SetErrorLevel 2
                ${IfNot} ${Silent}
                    MessageBox MB_OK|MB_ICONSTOP "ABORT: old PRIMARY loop/processes still running after the stop attempt (exit $0). New BACKUP is up (box reachable). Resolve at console, then re-run."
                ${EndIf}
                Abort
            ${EndIf}
            Exec '"$SYSDIR\wscript.exe" "$INSTDIR\start-primary.vbs"'
            DetailPrint "Non-admin: new PRIMARY started detached; both channels now on koidra-gateway."
        ${Else}
            ; Fresh / repair / reprovision — no old stack; master spawns both.
            Exec '"$SYSDIR\wscript.exe" "$INSTDIR\supervisor.vbs"'
            DetailPrint "Non-admin: KoidraGateway.lnk created and supervisor started (both channels)."
        ${EndIf}
    ${EndIf}

    ; ---- SUPERVISION-INTEGRITY POST-INSTALL VALIDATION ------------------- ;
    ; RCA: a supervised launcher spun forever on an exe filename absent from disk.
    ; Before this run reports success, verify the task/launcher -> exe binding
    ; actually resolves to a real file on disk:
    ;   (a) run-node2.cmd exists (it is what the SYSTEM task action and the
    ;       supervisor invoke — the stable indirection layer),
    ;   (b) the exe named by the pointer (current wins over default, same order
    ;       the launcher uses) exists,
    ;   (c) the launcher's literal fallback exe (${BIN_VERSIONED}) exists.
    ; SELF-CORRECT when the pointer names a missing exe but the fallback is good;
    ; FAIL LOUD (never claim success) when nothing runnable is on disk. Runs for
    ; BOTH admin + non-admin paths — the exe/pointer/launcher live in $INSTDIR
    ; either way. /S stays hang-free via the same ${IfNot} ${Silent} MessageBox
    ; pattern used everywhere else in this file.
    DetailPrint "Integrity: validating task/launcher exe-on-disk binding..."

    ; (a) run-node2.cmd — the target of the task action + supervisor.vbs.
    ${IfNot} ${FileExists} "$INSTDIR\run-node2.cmd"
        DetailPrint "INTEGRITY ABORT: $INSTDIR\run-node2.cmd is missing — the scheduled task / supervisor would invoke a launcher that is not on disk."
        SetErrorLevel 2
        ${IfNot} ${Silent}
            MessageBox MB_OK|MB_ICONSTOP "INTEGRITY ABORT: $INSTDIR\run-node2.cmd is missing. The scheduled task and supervisor both invoke this launcher; without it the channels can never start. Investigate the staging step and re-run."
        ${EndIf}
        Abort
    ${EndIf}

    ; (b) exe named by the pointer — current-koidra-gateway.txt if present, else
    ;     default-koidra-gateway.txt (the launcher's own current>default order).
    StrCpy $R2 ""          ; $R2 = pointer file actually consulted
    StrCpy $R3 ""          ; $R3 = exe name it names
    ${If} ${FileExists} "$INSTDIR\current-koidra-gateway.txt"
        StrCpy $R2 "$INSTDIR\current-koidra-gateway.txt"
    ${ElseIf} ${FileExists} "$INSTDIR\default-koidra-gateway.txt"
        StrCpy $R2 "$INSTDIR\default-koidra-gateway.txt"
    ${EndIf}
    ${If} $R2 != ""
        ClearErrors
        FileOpen $R4 "$R2" r
        ${IfNot} ${Errors}
            FileRead $R4 $R3
            FileClose $R4
            ${TrimNewLines} $R3 $R3   ; pointer content is one line; strip any CR/LF
        ${EndIf}
    ${EndIf}

    StrCpy $R5 0    ; $R5 = 1 when the pointed-to exe exists on disk
    ${If} $R3 != ""
    ${AndIf} ${FileExists} "$INSTDIR\$R3"
        StrCpy $R5 1
    ${EndIf}

    StrCpy $R6 0    ; $R6 = 1 when the literal fallback ${BIN_VERSIONED} exists
    ${If} ${FileExists} "$INSTDIR\${BIN_VERSIONED}"
        StrCpy $R6 1
    ${EndIf}

    ${If} $R5 == 1
        ; Pointer resolves to a real exe — the common, healthy path.
        DetailPrint "Integrity: pointer ($R2) -> $R3 exists on disk; task/launcher binding valid."
    ${ElseIf} $R6 == 1
        ; SELF-CORRECT: pointer names a missing exe, but the literal fallback
        ; (${BIN_VERSIONED}) IS on disk — rewrite the pointer to it so the launcher
        ; resolves a real file instead of spinning on the absent name.
        DetailPrint "INTEGRITY WARNING: pointer ($R2) names a missing exe ($R3); self-correcting to ${BIN_VERSIONED} (present on disk)."
        ${If} $R2 == ""
            StrCpy $R2 "$INSTDIR\current-koidra-gateway.txt"
        ${EndIf}
        FileOpen $R4 "$R2" w
        FileWrite $R4 "${BIN_VERSIONED}"
        FileClose $R4
        DetailPrint "Integrity: rewrote $R2 -> ${BIN_VERSIONED}; launcher now resolves a real exe on disk."
    ${Else}
        ; FAIL LOUD: neither the pointed-to exe nor the literal fallback is on
        ; disk — the supervised launcher would spin forever on an absent file.
        DetailPrint "INTEGRITY ABORT: no runnable exe on disk — pointer names '$R3' (absent) and fallback ${BIN_VERSIONED} is also absent."
        SetErrorLevel 2
        ${IfNot} ${Silent}
            MessageBox MB_OK|MB_ICONSTOP "INTEGRITY ABORT: no koidra-gateway exe is on disk. The version pointer names '$R3' (not present) and the launcher's literal fallback ${BIN_VERSIONED} is also missing. The supervised launcher would spin forever on an absent file. Investigate the exe staging (File /oname) and re-run."
        ${EndIf}
        Abort
    ${EndIf}
    DetailPrint "Integrity: task -> run-node2.cmd binding intact and an exe-on-disk is guaranteed."
SectionEnd

; --------------------------------------------------------------------------- ;
Section "-AutoFinalize"
    ; §7 (REVISED): auto-finalize replaces the old two-phase pattern. The installer
    ; stages + starts new channels, waits for them to stabilize, validates they're
    ; healthy, then auto-removes old persistence. /STAGE-ONLY skips this for the
    ; manual verify-first pattern. /FINALIZE still works as a standalone persistence-
    ; removal pass for the old workflow.
    ${If} $StageOnly == 1
        DetailPrint "STAGE-ONLY: old persistence left intact (operator will verify + run /FINALIZE manually)."
        ${IfNot} ${Silent}
            MessageBox MB_OK "koidra-gateway installed and started (STAGE-ONLY).$\n$\nOld persistence is LEFT INTACT. After external validation, run:$\n    koidra-gateway-setup.exe /FINALIZE"
        ${EndIf}
        Goto finalize_done
    ${EndIf}

    ${If} $Mode != "upgrade"
        ; Fresh/repair/reprovision have no old persistence to remove.
        DetailPrint "AUTO-FINALIZE: mode=$Mode — no old persistence to remove. Install complete."
        Goto finalize_done
    ${EndIf}

    ; --- AUTO-FINALIZE VALIDATION (upgrade mode only) ---
    ; Wait for new channels to stabilize, then validate before removing old.
    DetailPrint "AUTO-FINALIZE: waiting 30s for new channels to stabilize..."
    ; Use ping for delay (no PS quoting issues, works on all Windows versions).
    nsExec::ExecToLog 'ping -n 31 127.0.0.1'
    Pop $0

    ; Check 1: new gateway processes alive.
    ; Write a .cmd helper to count processes (avoids inline PS quoting bugs that
    ; caused the auto-finalize false-negative on hanyu — the nested quotes in
    ; the NSIS→cmd→PowerShell chain mangled the closing paren).
    FileOpen $R8 "$INSTDIR\count-gw.cmd" w
    FileWrite $R8 '@echo off$\r$\n'
    FileWrite $R8 'tasklist /nh /fo csv ^| find /c "koidra-gateway"$\r$\n'
    FileClose $R8
    nsExec::ExecToStack '"$INSTDIR\count-gw.cmd"'
    Pop $0
    Pop $R9
    ; tasklist+find returns count on stdout; trim whitespace by converting to int.
    IntOp $R9 $R9 + 0
    ${If} $R9 < 2
        DetailPrint "AUTO-FINALIZE FAILED: fewer than 2 koidra-gateway processes running ($R9). Keeping old persistence."
        ${IfNot} ${Silent}
            MessageBox MB_OK|MB_ICONEXCLAMATION "AUTO-FINALIZE: new channels did not start properly (found $R9 gateway processes, expected >=2). OLD persistence kept as fallback. Investigate and re-run with /FINALIZE when ready."
        ${EndIf}
        Delete "$INSTDIR\count-gw.cmd"
        Goto finalize_done
    ${EndIf}
    Delete "$INSTDIR\count-gw.cmd"
    DetailPrint "AUTO-FINALIZE: $R9 gateway processes running."

    ; Check 2: boot-state.json written (gateway writes this on successful startup)
    ${IfNot} ${FileExists} "$INSTDIR\.boot-state.json"
        DetailPrint "AUTO-FINALIZE FAILED: .boot-state.json not written — gateway may not have registered on tailnet. Keeping old persistence."
        ${IfNot} ${Silent}
            MessageBox MB_OK|MB_ICONEXCLAMATION "AUTO-FINALIZE: .boot-state.json was not written — the gateway may not have registered on the tailnet. OLD persistence kept as fallback."
        ${EndIf}
        Goto finalize_done
    ${EndIf}
    DetailPrint "AUTO-FINALIZE: .boot-state.json present — gateway registered."

    ; All checks passed — auto-finalize (remove old persistence).
    DetailPrint "AUTO-FINALIZE: validation PASSED — removing old koidra-ssh persistence..."
    Call DoFinalize
    DetailPrint "AUTO-FINALIZE: old persistence removed. Install complete (single-run)."
    ${IfNot} ${Silent}
        MessageBox MB_OK "koidra-gateway installed, validated, and finalized in a single run.$\n$\nOld persistence has been removed. The new koidra-gateway channels are running and registered on the tailnet."
    ${EndIf}

    finalize_done:
SectionEnd

; --------------------------------------------------------------------------- ;
Section "Uninstall"
    ; Removes ONLY koidra-gateway artifacts. Never touches koidra-ssh.
    Delete "$INSTDIR\${BIN_VERSIONED}"
    Delete "$INSTDIR\run-node2.cmd"
    Delete "$INSTDIR\supervisor.vbs"
    Delete "$INSTDIR\start-primary.vbs"
    Delete "$INSTDIR\start-backup.vbs"
    Delete "$INSTDIR\start-primary-old.vbs"
    Delete "$INSTDIR\start-backup-old.vbs"
    Delete "$INSTDIR\extract-authkey.ps1"
    Delete "$INSTDIR\stop-old-stack.ps1"
    Delete "$INSTDIR\check-console.ps1"
    Delete "$INSTDIR\current-koidra-gateway.txt"
    Delete "$INSTDIR\default-koidra-gateway.txt"
    Delete "$INSTDIR\old-install-dir.txt"
    Delete "$INSTDIR\authkey.txt"
    Delete "$INSTDIR\koidra-diag.txt"
    Delete "$INSTDIR\primary.json"
    Delete "$INSTDIR\backup.json"
    Delete "$INSTDIR\uninstall-koidra-gateway.exe"
    RMDir "$INSTDIR"

    nsExec::ExecToLog 'schtasks /delete /tn "KoidraGateway-primary" /f'
    Pop $0
    nsExec::ExecToLog 'schtasks /delete /tn "KoidraGateway-backup" /f'
    Pop $0
    SetShellVarContext current
    Delete "$SMSTARTUP\KoidraGateway.lnk"
    SetShellVarContext all
    Delete "$SMSTARTUP\KoidraGateway.lnk"
SectionEnd

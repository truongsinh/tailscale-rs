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
;    Also detect an existing koidra-gateway dir (re-run / repair — idempotent).
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
; 5. STOP OLD BEFORE START NEW: stop-old-stack.ps1 ends the old KoidraSSH-* tasks,
;    kills every ssh_shell* tree + the old supervise loops, and VERIFIES zero
;    remain, BEFORE any new task is /run. Never two processes on one keyfile.
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
; Build:  makensis -DGW_SHA=<sha> installer.nsi
;   Stage beside this .nsi: koidra_gateway.exe (raw Cargo example output),
;   run-node2.cmd, supervisor.vbs, start-{primary,backup}.vbs,
;   start-{primary,backup}-old.vbs, extract-authkey.ps1, stop-old-stack.ps1.
;   For a FRESH (net-new / lab) box, also stage primary.json/backup.json and/or
;   authkey.txt beside the .nsi, or set KOIDRA_PRIMARY_AUTHKEY in the environment.
; =============================================================================

!include "LogicLib.nsh"
!include "MUI2.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"   ; GetParameters / GetOptions

Name "Koidra Gateway"
OutFile "koidra-gateway-setup.exe"
Unicode True
ShowInstDetails show
; The installer is launched at console by the operator. It self-detects the
; existing layout; it does NOT auto-elevate (Win7 non-admin boxes can't).
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
Var ProgramData   ; %PROGRAMDATA%   (via ReadEnvStr)
Var LocalAppDir   ; %LOCALAPPDATA%  (via ReadEnvStr)
Var BaseDir       ; ProgramData (admin) or LocalAppData (non-admin)
Var OldDir        ; <BaseDir>\koidra-ssh
Var Mode          ; "upgrade" | "fresh" | "repair"

; Directory is COMPUTED from the detected layout — never operator-chosen (a wrong
; dir loses identity). So no MUI_PAGE_DIRECTORY / COMPONENTS.
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

; --------------------------------------------------------------------------- ;
Function .onInit
    StrCpy $Finalize 0

    ; /FINALIZE — persistence-removal pass only (§7). No install, no identity, no
    ; new tasks; just remove the OLD persistence after external validation.
    ${GetParameters} $R0
    ClearErrors
    ${GetOptions} $R0 "/FINALIZE" $R1
    ${IfNot} ${Errors}
        StrCpy $Finalize 1
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
            MessageBox MB_OK|MB_ICONSTOP "An admin (ProgramData) koidra-ssh install is present at $ProgramData\koidra-ssh, but this installer is NOT running elevated.$\n$\nRe-run koidra-gateway-setup.exe as Administrator. Refusing to install a divergent per-user copy with fresh keys next to the live SYSTEM stack."
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
        ; Existing koidra-gateway dir with no koidra-ssh -> repair/re-run.
        ${If} ${FileExists} "$BaseDir\koidra-gateway\*.*"
            StrCpy $Mode "repair"
        ${EndIf}
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
    MessageBox MB_OK "Finalize complete: old KoidraSSH-* tasks and KoidraSSH.lnk removed. The old koidra-ssh directory is left on disk for the coordinator's list-before-delete pass."
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
    File /oname=${BIN_VERSIONED} "${BIN_SRC}"

    ; Seed the version pointer with the versioned binary name (never a bare
    ; unversioned name). The launcher reads this first.
    FileOpen $0 "$INSTDIR\current-koidra-gateway.txt" w
    FileWrite $0 "${BIN_VERSIONED}"
    FileClose $0

    ; Record the old dir so the rollback launchers (start-*-old.vbs) can find it.
    FileOpen $0 "$INSTDIR\old-install-dir.txt" w
    FileWrite $0 "$OldDir"
    FileClose $0

    ; ---- IDENTITY (§2) --------------------------------------------------- ;
    ${If} $Mode == "upgrade"
        ${IfNot} ${FileExists} "$OldDir\primary.json"
            MessageBox MB_OK|MB_ICONSTOP "UPGRADE ABORT: $OldDir\primary.json is missing. Refusing to mint a fresh node identity. Stage the box's real identity json or investigate before proceeding."
            Abort
        ${EndIf}
        ${IfNot} ${FileExists} "$OldDir\backup.json"
            MessageBox MB_OK|MB_ICONSTOP "UPGRADE ABORT: $OldDir\backup.json is missing. Refusing to mint a fresh node identity."
            Abort
        ${EndIf}
        ; Byte-identical copy -> same nodeId + same 100.x IP.
        CopyFiles /SILENT "$OldDir\primary.json" "$INSTDIR\primary.json"
        CopyFiles /SILENT "$OldDir\backup.json"  "$INSTDIR\backup.json"
        DetailPrint "Identity: copied primary.json + backup.json from $OldDir (byte-identical)."
    ${ElseIf} $Mode == "repair"
        ; Keep the already-present new jsons; only re-stage if genuinely absent.
        ${IfNot} ${FileExists} "$INSTDIR\primary.json"
            ${If} ${FileExists} "$EXEDIR\primary.json"
                CopyFiles /SILENT "$EXEDIR\primary.json" "$INSTDIR\primary.json"
            ${Else}
                MessageBox MB_OK|MB_ICONSTOP "REPAIR ABORT: $INSTDIR\primary.json missing and no staged copy beside the installer."
                Abort
            ${EndIf}
        ${EndIf}
        ${IfNot} ${FileExists} "$INSTDIR\backup.json"
            ${If} ${FileExists} "$EXEDIR\backup.json"
                CopyFiles /SILENT "$EXEDIR\backup.json" "$INSTDIR\backup.json"
            ${Else}
                MessageBox MB_OK|MB_ICONSTOP "REPAIR ABORT: $INSTDIR\backup.json missing and no staged copy beside the installer."
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
            MessageBox MB_OK|MB_ICONSTOP "UPGRADE ABORT: could not extract the baked -k tskey-... auth key from $OldDir\run-node.cmd (exit $0). Refusing to ship an empty key."
            Abort
        ${EndIf}
        ${IfNot} ${FileExists} "$INSTDIR\authkey.txt"
            MessageBox MB_OK|MB_ICONSTOP "UPGRADE ABORT: authkey.txt was not produced from $OldDir."
            Abort
        ${EndIf}
        DetailPrint "Auth key: extracted baked token from $OldDir -> authkey.txt."
    ${Else}
        ; FRESH / REPAIR — bake the operator-supplied key TO DISK at install time
        ; (reading env NOW to write a file is fine; only LAUNCH-time env is banned).
        ${IfNot} ${FileExists} "$INSTDIR\authkey.txt"
            ${If} ${FileExists} "$EXEDIR\authkey.txt"
                CopyFiles /SILENT "$EXEDIR\authkey.txt" "$INSTDIR\authkey.txt"
            ${Else}
                ReadEnvStr $2 "KOIDRA_PRIMARY_AUTHKEY"
                ${If} $2 == ""
                    MessageBox MB_OK|MB_ICONSTOP "ABORT: no auth key for a fresh install. Stage authkey.txt beside the installer or set KOIDRA_PRIMARY_AUTHKEY before running."
                    Abort
                ${EndIf}
                FileOpen $3 "$INSTDIR\authkey.txt" w
                FileWrite $3 "$2"
                FileClose $3
            ${EndIf}
        ${EndIf}
        DetailPrint "Auth key: baked to authkey.txt (fresh/repair)."
    ${EndIf}

    ; ---- STOP OLD STACK (§5) — upgrade only, BEFORE any new task /run ----- ;
    ${If} $Mode == "upgrade"
        DetailPrint "Stopping old koidra-ssh stack and verifying zero ssh_shell* remain..."
        nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\stop-old-stack.ps1" "$OldDir" "$IsAdmin"'
        Pop $0
        ${If} $0 != 0
            MessageBox MB_OK|MB_ICONSTOP "ABORT: old ssh_shell processes are still running after the stop attempt (exit $0). Refusing to start the new stack over a live old one (two processes on one keyfile = orphan node). Resolve manually, then re-run."
            Abort
        ${EndIf}
        DetailPrint "Old stack confirmed down."
    ${EndIf}

    WriteUninstaller "$INSTDIR\uninstall-koidra-gateway.exe"
SectionEnd

; --------------------------------------------------------------------------- ;
Section "Start koidra-gateway channels" SecStart
    ${If} $IsAdmin == 1
        ; SYSTEM tasks, onstart, HIGHEST. Both channels on port 22 (§6).
        ; /tr has NO nested quotes (board gotcha): ProgramData path has no spaces,
        ; so the whole `cmd /c <path> <chan> 22` is a single outer-quoted value.
        nsExec::ExecToLog 'schtasks /create /tn "KoidraGateway-primary" /ru SYSTEM /sc onstart /rl HIGHEST /tr "cmd /c $INSTDIR\run-node2.cmd primary 22" /f'
        Pop $0
        nsExec::ExecToLog 'schtasks /create /tn "KoidraGateway-backup" /ru SYSTEM /sc onstart /rl HIGHEST /tr "cmd /c $INSTDIR\run-node2.cmd backup 22" /f'
        Pop $0
        ; Start now (detached by construction — SYSTEM tasks are not session children).
        nsExec::ExecToLog 'schtasks /run /tn "KoidraGateway-primary"'
        Pop $0
        nsExec::ExecToLog 'schtasks /run /tn "KoidraGateway-backup"'
        Pop $0
        DetailPrint "Admin: KoidraGateway-primary/-backup created (onstart) and started."
    ${Else}
        ; Non-admin: ONE Startup shortcut -> ONE supervisor that launches BOTH
        ; channel loops (symmetric bring-up, no per-channel onlogon task, no
        ; primary double-launch). Matches the old KoidraSSH.lnk contract.
        CreateShortcut "$SMSTARTUP\KoidraGateway.lnk" "$SYSDIR\wscript.exe" '"$INSTDIR\supervisor.vbs"' "$INSTDIR\${BIN_VERSIONED}" 0
        ; Start the supervisor NOW, detached (Exec does not wait — the supervisor
        ; loops forever). It spawns start-primary.vbs + start-backup.vbs.
        Exec '"$SYSDIR\wscript.exe" "$INSTDIR\supervisor.vbs"'
        DetailPrint "Non-admin: KoidraGateway.lnk created and supervisor started (both channels)."
    ${EndIf}
SectionEnd

; --------------------------------------------------------------------------- ;
Section "-TwoPhaseReminder"
    ; §7: old persistence is intentionally LEFT INTACT this run.
    DetailPrint "TWO-PHASE: old KoidraSSH-* tasks / KoidraSSH.lnk LEFT INTACT as boot fallback."
    DetailPrint "After EXTERNAL validation, run: koidra-gateway-setup.exe /FINALIZE  to remove old persistence."
    MessageBox MB_OK "koidra-gateway installed and started.$\n$\nThe OLD koidra-ssh persistence (tasks / Startup shortcut) and directory are LEFT INTACT as the boot fallback.$\n$\nAfter the coordinator's external validation passes (nodeId + IP + clientVersion unchanged, real SSH banner+exec, rx advancing), run:$\n    koidra-gateway-setup.exe /FINALIZE$\nto remove the old persistence. Directory deletion is a separate coordinator pass."
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
    Delete "$INSTDIR\current-koidra-gateway.txt"
    Delete "$INSTDIR\old-install-dir.txt"
    Delete "$INSTDIR\authkey.txt"
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

; installer.nsi — NSIS installer source for koidra-gateway (Windows).
;
; Produces koidra-gateway-setup.exe. Installs the supervisor + the bootstrap
; binary, creates the scheduled tasks (admin path) or the Startup-group
; shortcut (non-admin path), and sets the per-box env vars.
;
; Build:
;   makensis installer.nsi
;
; The resulting installer detects elevation: if running elevated, installs to
; C:\ProgramData\koidra-gateway\ and creates SYSTEM scheduled tasks; if not,
; installs to %LOCALAPPDATA%\koidra-gateway\ and creates a Startup shortcut
; + per-user scheduled task. Both paths end up with:
;   - run-node2.cmd + supervisor.vbs + koidra_gateway.exe + <channel>.json
;   - current-koidra-gateway.txt seeded with the shipped binary's name
;   - the channel launched on every boot via the appropriate mechanism.
;
; This is a from-scratch rebuild of the koidra-ssh installer under the new name.
; The original koidra-ssh installer source lived in the on-box
; koidra-ssh-fleet/ tree and was never checked in. This is the canonical source
; going forward.

!include "LogicLib.nsh"
!include "MUI2.nsh"
!include "x64.nsh"

Name "Koidra Gateway"
OutFile "koidra-gateway-setup.exe"
Unicode True
ShowInstDetails show
RequestExecutionLevel user ; auto-elevate only if user picks the admin path

; Version metadata — bump per release. The installer itself doesn't carry the
; binary version (that's baked into koidra_gateway.exe via build.rs); this is
; just the installer/UI version.
VIProductVersion "0.4.0.254"
VIAddVersionKey "ProductName" "Koidra Gateway"
VIAddVersionKey "CompanyName" "Koidra"
VIAddVersionKey "LegalCopyright" "© 2026 Koidra"
VIAddVersionKey "FileVersion" "0.4.0.254"
VIAddVersionKey "ProductVersion" "0.4.0.254"

; Files to install — expected alongside this .nsi at build time (the build
; recipe copies them in from target/<triple>/release/examples/).
!define BIN_PRIMARY "koidra_gateway.exe"
!define SUPERVISOR_CMD "run-node2.cmd"
!define SUPERVISOR_VBS "supervisor.vbs"

Var InstallDir
Var IsAdmin
Var AuthKeyPrimary
Var AuthKeyBackup

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Function .onInit
    ; Detect elevation. The installer offers admin vs per-user install based
    ; on this, rather than forcing UAC — non-admin boxes (Win7 scherze/redsun
    ; path) can't elevate.
    UserInfo::GetAccountType
    Pop $0
    ${If} $0 == "Admin"
        StrCpy $IsAdmin 1
        StrCpy $InstallDir "$PROGRAMDATA\koidra-gateway"
    ${Else}
        StrCpy $IsAdmin 0
        StrCpy $InstallDir "$LOCALAPPDATA\koidra-gateway"
    ${EndIf}
    StrCpy $INSTDIR $InstallDir

    ; Auth keys come from env vars set by the operator running the installer
    ; (or passed via /D on the makensis command line for unattended installs).
    ReadEnvStr $AuthKeyPrimary "KOIDRA_PRIMARY_AUTHKEY"
    ReadEnvStr $AuthKeyBackup  "KOIDRA_BACKUP_AUTHKEY"
FunctionEnd

Section "Koidra Gateway (required)" SecCore
    SectionIn RO
    SetOutPath "$INSTDIR"

    ; Core files.
    File "${BIN_PRIMARY}"
    File "${SUPERVISOR_CMD}"
    File "${SUPERVISOR_VBS}"

    ; Seed current-koidra-gateway.txt with the shipped binary so the supervisor
    ; has something to launch on first boot before the updater ever runs.
    FileOpen $0 "$INSTDIR\current-koidra-gateway.txt" w
    FileWrite $0 "${BIN_PRIMARY}"
    FileClose $0

    ; Per-box env vars (machine-wide on admin, per-user on non-admin).
    ${If} $IsAdmin == 1
        SetShellVarContext all
        WriteEnvStr "KOIDRA_INSTALL_DIR" "$INSTDIR"
        WriteEnvStr "KOIDRA_MANIFEST_URL" "https://github.com/truongsinh/tailscale-rs/releases/download/koidra-gateway-bootstrap/koidra-gateway-manifest.json"
        WriteEnvStr "AUTHKEY" "$AuthKeyPrimary"
    ${Else}
        SetShellVarContext current
        WriteEnvStr "KOIDRA_INSTALL_DIR" "$INSTDIR"
        WriteEnvStr "KOIDRA_MANIFEST_URL" "https://github.com/truongsinh/tailscale-rs/releases/download/koidra-gateway-bootstrap/koidra-gateway-manifest.json"
        WriteEnvStr "AUTHKEY" "$AuthKeyPrimary"
    ${EndIf}

    ; Channel identity files. Operator pre-stages primary.json / backup.json
    ; in the build dir; the installer just copies them.
    ${If} ${FileExists} "$EXEDIR\primary.json"
        CopyFiles /SILENT "$EXEDIR\primary.json" "$INSTDIR\primary.json"
    ${EndIf}
    ${If} ${FileExists} "$EXEDIR\backup.json"
        CopyFiles /SILENT "$EXEDIR\backup.json" "$INSTDIR\backup.json"
    ${EndIf}

    ; Uninstaller.
    WriteUninstaller "$INSTDIR\uninstall-koidra-gateway.exe"
SectionEnd

Section "Scheduled Task — primary" SecTaskPrimary
    ${If} $IsAdmin == 1
        ; SYSTEM principal, survives logoff. Action: cmd /c run-node2.cmd primary 22
        nsExec::ExecToLog 'schtasks /create /tn "KoidraGateway-primary" /ru SYSTEM /sc onstart /rl HIGHEST /tr "cmd /c \"$INSTDIR\run-node2.cmd\" primary 22" /f'
        nsExec::ExecToLog 'schtasks /run /tn "KoidraGateway-primary"'
    ${Else}
        ; Per-user task (no SYSTEM, runs at logon).
        nsExec::ExecToLog 'schtasks /create /tn "KoidraGateway-primary" /sc onlogon /tr "wscript.exe \"$INSTDIR\supervisor.vbs\" primary 22" /f'
        ; Also drop a Startup shortcut as belt-and-braces for the non-admin path.
        CreateShortcut "$SMSTARTUP\KoidraGateway.lnk" "wscript.exe" "\"$INSTDIR\supervisor.vbs\" primary 22" "$INSTDIR\${BIN_PRIMARY}" 0
    ${EndIf}
SectionEnd

Section "Scheduled Task — backup" SecTaskBackup
    ${If} $IsAdmin == 1
        nsExec::ExecToLog 'schtasks /create /tn "KoidraGateway-backup" /ru SYSTEM /sc onstart /rl HIGHEST /tr "cmd /c \"$INSTDIR\run-node2.cmd\" backup 23" /f'
        nsExec::ExecToLog 'schtasks /run /tn "KoidraGateway-backup"'
    ${Else}
        nsExec::ExecToLog 'schtasks /create /tn "KoidraGateway-backup" /sc onlogon /tr "wscript.exe \"$INSTDIR\supervisor.vbs\" backup 23" /f'
    ${EndIf}
SectionEnd

Section "Uninstall"
    Delete "$INSTDIR\${BIN_PRIMARY}"
    Delete "$INSTDIR\${SUPERVISOR_CMD}"
    Delete "$INSTDIR\${SUPERVISOR_VBS}"
    Delete "$INSTDIR\current-koidra-gateway.txt"
    Delete "$INSTDIR\primary.json"
    Delete "$INSTDIR\backup.json"
    Delete "$INSTDIR\uninstall-koidra-gateway.exe"
    RMDir "$INSTDIR"

    nsExec::ExecToLog 'schtasks /delete /tn "KoidraGateway-primary" /f'
    nsExec::ExecToLog 'schtasks /delete /tn "KoidraGateway-backup" /f'
    Delete "$SMSTARTUP\KoidraGateway.lnk"
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore}        "Core binary + supervisor scripts (required)."
    !insertmacro MUI_DESCRIPTION_TEXT ${SecTaskPrimary} "Primary channel: launches on boot, restarts on crash."
    !insertmacro MUI_DESCRIPTION_TEXT ${SecTaskBackup}  "Backup channel: redundant tailnet IP, separate identity."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

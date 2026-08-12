; blazma.nt installer customisation.
;
; The only extra step over a standard NSIS install is checking for Npcap and
; telling the user how to get it. The installer deliberately does NOT download
; or silently install Npcap: that is a kernel-mode driver with its own licence,
; and installing it behind the user's back would be wrong.

!macro customInit
  ; Npcap registers its runtime under System32\Npcap. Check both the 64-bit and
  ; the redirected view so the test works regardless of installer bitness.
  ${IfNot} ${FileExists} "$SYSDIR\Npcap\wpcap.dll"
  ${AndIfNot} ${FileExists} "$WINDIR\System32\Npcap\wpcap.dll"
  ${AndIfNot} ${FileExists} "$SYSDIR\wpcap.dll"
    MessageBox MB_YESNO|MB_ICONEXCLAMATION \
      "Npcap was not found.$\r$\n$\r$\nblazma.nt needs Npcap to capture network traffic. Without it the application still installs and runs, but live capture stays unavailable.$\r$\n$\r$\nOpen the Npcap download page now?$\r$\n(Enable 'WinPcap API-compatible mode' during its setup.)" \
      IDNO skip_npcap
    ExecShell "open" "https://npcap.com/#download"
    skip_npcap:
  ${EndIf}
!macroend

!macro customUnInstall
  ; Application data (the SQLite database with the user's captured metadata) is
  ; left in place unless the user removes it, so an upgrade never destroys it.
  ${IfNot} ${Silent}
    MessageBox MB_YESNO|MB_ICONQUESTION \
      "Also delete blazma.nt's stored data (database, settings and logs)?" \
      IDNO keep_data
    RMDir /r "$APPDATA\blazma.nt"
    keep_data:
  ${EndIf}
!macroend

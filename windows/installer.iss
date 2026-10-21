; SPDX-License-Identifier: GPL-3.0-only
; Inno Setup 6 script for "Pax for iPhone set-up" (Windows). Per-user install: no
; administrator rights, nothing system-wide, nothing that runs at startup. It installs the
; set-up app only; it does not filter or protect the PC.
; Build: ISCC /DAppVersion=0.1.0 /DSourceDir=dist\PaxSetup /DOutDir=dist windows\installer.iss
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\PaxSetup"
#endif
#ifndef OutDir
  #define OutDir "..\dist"
#endif

[Setup]
AppId={{6E8BA81E-2A38-4C9D-9F4B-C9D4DFF7F9FB}
AppName=Pax for iPhone set-up
AppVersion={#AppVersion}
AppPublisher=Pax Technologies
AppPublisherURL=https://paxpeace.com
AppSupportURL=https://paxpeace.com
DefaultDirName={localappdata}\Programs\Pax for iPhone set-up
DefaultGroupName=Pax
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutDir}
OutputBaseFilename=PaxSetup-{#AppVersion}-windows-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\LICENSE
UninstallDisplayName=Pax for iPhone set-up
#if FileExists(AddBackslash(SourcePath) + "build\pax.ico")
SetupIconFile=build\pax.ico
#endif

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{autoprograms}\Pax for iPhone set-up"; Filename: "{app}\PaxSetup.exe"
Name: "{autodesktop}\Pax for iPhone set-up"; Filename: "{app}\PaxSetup.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Add a desktop shortcut"; Flags: unchecked

[Run]
Filename: "{app}\PaxSetup.exe"; Description: "Open Pax for iPhone set-up"; Flags: nowait postinstall skipifsilent

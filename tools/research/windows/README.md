# Windows license-info research harness

Research-only. Does **not** implement IKEv2 Notify `0xF100`, does not
change Linux VPN behavior, and does not modify FortiClient.

Source: `dump-license-info.cpp`

The program loads the **official** installed x64 DLL:

`C:\Program Files\Fortinet\FortiClient\utilsdll.dll`

calls `GenRawLicenseInfo2(&out, nullptr)`, writes `strlen+1` bytes
(including the trailing NUL) to `license-info.raw`, and prints KEY
names only. Values are never printed.

`license-info.raw` is identifier material. Do not commit it, paste it,
or attach it to issues.

The official DLL may resolve the local hostname while building `IP=`
(static analysis §12.9). The harness itself does not open sockets,
start a VPN, write the registry, change the DLL search path, or call
`ipsec.exe`.

`utilsdll.dll` DllMain **rejects** process images that are not under
the FortiClient `INSTALLDIR` registry value (§12.11). A harness exe
in Downloads is expected to fail with:

- `GetLastError=126` (`ERROR_MOD_NOT_FOUND`) if private dependencies
  are not on the search path (typical when cwd is Downloads)
- `GetLastError=1114` (`ERROR_DLL_INIT_FAILED`) if the DLL and
  dependencies load but DllMain returns FALSE (typical when cwd is
  the FortiClient directory so private DLLs resolve, but the host
  exe path is still Downloads)

Do **not** copy the harness into `C:\Program Files\Fortinet\FortiClient`
and do not change FortiClient. Those LoadLibrary failures are
explained by static analysis; they are not a reason to implement
Notify `0xF100`.

## Build (preferred: Microsoft x64)

From an **x64** Visual Studio Developer Command Prompt
(`x64 Native Tools Command Prompt for VS`):

```bat
cl /std:c++17 /EHsc dump-license-info.cpp /Fe:dump-license-info.exe
```

A 32-bit `cl` will produce an exe that cannot load the x64 DLL.

## Build (MinGW-w64, optional)

```bat
x86_64-w64-mingw32-g++ -std=c++17 -O2 -o dump-license-info.exe dump-license-info.cpp -ladvapi32
```

Prefer the Microsoft x64 build.

## Run

```bat
mkdir C:\Users\mwi\Downloads\fvl-license-research
cd C:\Users\mwi\Downloads\fvl-license-research
```

Copy `dump-license-info.cpp` into that directory, build, then:

```bat
.\dump-license-info.exe
Get-Item .\license-info.raw | Select-Object Length
Get-FileHash .\license-info.raw -Algorithm SHA256
```

If `LoadLibraryW` fails, send back the harness **stderr** diagnostic
block (`GetLastError`, `FormatMessage`, host exe, cwd, INSTALLDIR
prefix check, sibling `GetFileAttributesW` lines). Do not change
the FortiClient install.

## Optional read-only Windows checks

These only list files, hashes, dependents, and registry values.
Do not copy DLLs, register anything, or start/stop services.

```powershell
Get-ChildItem "C:\Program Files\Fortinet\FortiClient" -File |
    Where-Object { $_.Name -match 'utilsdll|FCCryptDLL|FortiVpnDll2|libssl-3-x64|libcrypto-3-x64' } |
    Select-Object Name, Length
Get-FileHash "C:\Program Files\Fortinet\FortiClient\utilsdll.dll" -Algorithm SHA256
Get-ItemProperty "HKLM:\SOFTWARE\Fortinet\FortiClient" |
    Select-Object INSTALLDIR
where.exe dump-license-info.exe
```

If Visual Studio `dumpbin` is on PATH:

```bat
dumpbin /dependents "C:\Program Files\Fortinet\FortiClient\utilsdll.dll"
```

If LoadLibrary succeeds, send back only:

- the harness stdout structural report
- `Length` of `license-info.raw`
- SHA256

Do **not** paste the contents of `license-info.raw`.

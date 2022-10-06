MitiMon - Mitigations Monitor for Windows
=========================================

Summary
-------

When things go wrong after [setting new mitigation policies on a Windows process](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy), it is often hard to know what exactly is going wrong.
`mitimon` catches the ETW events issued by the kernel when a mitigation policy denies an operation.
It provides the symbolized kernel and stack traces at the moment when the event was generated, which can help pinpoint exactly what code is being impacted by the new mitigation policy.

`mitimon` was initially developed to help debug problems that appear in Mozilla Firefox on Windows after deploying stricter mitigation policies.
It should work as-is for other projects, and it can easily be adapted to get symbolized stack traces for ETW events sent from different ETW providers.

Note: It is very likely possible to use `xperf` to do the same thing.

Usage
-----

- `mitimon` must run as administrator.
- It will write results to `output.txt`.
- It will create and use the `C:\MozSym` folder. Delete this folder after using the tool.
- Make sure that there are files called `DbgHelp.dll` and `SymSrv.dll` in the same folder as `mitimon.exe`.

Limitations
-----------

- 64-bit only.
- Kernel stack traces will be wrong if ETW events are not generated by calling `EtwWrite`. This should never happen unless you are adapting the code for a different provider.

Building requirements
---------------------

- Visual Studio 2022.
- A recent Windows SDK.
- C++20.
- The [krabsetw NuGet package](https://www.nuget.org/packages/Microsoft.O365.Security.Krabsetw/).
- Build in Release x64.
- Copy `DbgHelp.dll` and `SymSrv.dll` from `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64` to the produced binary's folder.
- Run the binary as administrator.

Shipping
--------

- Remember to provide copies of `DbgHelp.dll` and `SymSrv.dll` from `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64` with the produced binary.

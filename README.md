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

Example output
--------------

```
TaskName KERNEL_MITIGATION_TASK_PROHIBIT_DYNAMIC_CODE
EventId 2
ProcessId 0x00002550
ThreadId 0x00003df8

Call Stack:
   0xfffff8076d22e41c ntoskrnl+0x22e41c ntoskrnl!EtwWrite+0x2c
   0xfffff8076d93a14a ntoskrnl+0x93a14a ntoskrnl!EtwpTimLogMitigationForProcess+0x156
   0xfffff8076d93975e ntoskrnl+0x93975e ntoskrnl!EtwTimLogProhibitDynamicCode+0x36
   0xfffff8076d7f4674 ntoskrnl+0x7f4674 ntoskrnl!MiArbitraryCodeBlocked+0x1ad400
   0xfffff8076d28e947 ntoskrnl+0x28e947 ntoskrnl!MiAllowProtectionChange+0x123
   0xfffff8076d62aca2 ntoskrnl+0x62aca2 ntoskrnl!MiAllocateVirtualMemory+0x422
   0xfffff8076d647ccb ntoskrnl+0x647ccb ntoskrnl!NtAllocateVirtualMemory+0x1ab
   0xfffff8076d40a9b8 ntoskrnl+0x40a9b8 ntoskrnl!KiSystemServiceCopyEnd+0x28
   0x00007ffa676ed304 ntdll+0x9d304 ntdll!NtAllocateVirtualMemory+0x14
   0x00007ffa65141998 KernelBase+0x61998 KernelBase!VirtualAlloc+0x48
   0x00007ffa50800854 mozglue+0x10854 mozglue!mozilla::interceptor::MMPolicyInProcess::MaybeCommitNextPage+0x94 /builds/worker/workspace/obj-build/dist/include/mozilla/interceptor/MMPolicies.h:594+0x19
   0x00007ffa508006af mozglue+0x106af mozglue!mozilla::interceptor::VMSharingPolicyUnique<mozilla::interceptor::MMPolicyInProcess>::GetNextTrampoline+0x2f /builds/worker/workspace/obj-build/dist/include/mozilla/interceptor/VMSharingPolicies.h:157+0xd
   0x00007ffa508004c8 mozglue+0x104c8 mozglue!mozilla::interceptor::WindowsDllDetourPatcher<mozilla::interceptor::VMSharingPolicyShared>::AddHook+0xf8 /builds/worker/workspace/obj-build/dist/include/mozilla/interceptor/PatcherDetour.h:451+0x4a
   0x00007ffa50800018 mozglue+0x10018 mozglue!mozilla::interceptor::WindowsDllInterceptor<mozilla::interceptor::VMSharingPolicyShared>::AddDetour+0x48 /builds/worker/workspace/obj-build/dist/include/nsWindowsDllInterceptor.h:522+0x11
   0x00007ffa507fff55 mozglue+0xff55 mozglue!mozilla::interceptor::WindowsDllInterceptor<mozilla::interceptor::VMSharingPolicyShared>::AddDetour+0x115 /builds/worker/workspace/obj-build/dist/include/nsWindowsDllInterceptor.h:476+0x11
   0x00007ffa507ffe22 mozglue+0xfe22 mozglue!mozilla::interceptor::FuncHook<mozilla::interceptor::WindowsDllInterceptor<mozilla::interceptor::VMSharingPolicyShared>,long (*)(wchar_t *, unsigned long *, _UNICODE_STRING *, void **)>::InitOnceCallback+0x22 /builds/worker/checkouts/gecko/toolkit/xre/dllservices/mozglue/nsWindowsDllInterceptor.h:203+0x0
   0x00007ffa67693900 ntdll+0x43900 ntdll!RtlRunOnceExecuteOnce+0x90
   0x00007ffa6513a70b KernelBase+0x5a70b KernelBase!InitOnceExecuteOnce+0xb
   0x00007ffa5080bfbc mozglue+0x1bfbc mozglue!DllBlocklist_Initialize+0x17c /builds/worker/checkouts/gecko/toolkit/xre/dllservices/mozglue/WindowsDllBlocklist.cpp:633+0x0
   0x00007ff72a4b0895 firefox+0x20895 firefox!wmain+0x455 /builds/worker/checkouts/gecko/toolkit/xre/nsWindowsWMain.cpp:167+0x1b9
   0x00007ff72a4c0398 firefox+0x30398 firefox!__scrt_common_main_seh+0x10c d:\agent\_work\2\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl:288+0x22
   0x00007ffa65e47034 kernel32+0x17034 kernel32!BaseThreadInitThunk+0x14
   0x00007ffa676a26a1 ntdll+0x526a1 ntdll!RtlUserThreadStart+0x21

ProcessPathLength 0x003b
ProcessPath L"\Device\HarddiskVolume4\AppData\Firefox\firefox\firefox.exe"
ProcessCommandLineLength 0x015d
ProcessCommandLine L""D:\AppData\Firefox\firefox\firefox.exe" -contentproc --channel="2780.7.1342907712\841410979" -parentBuildID 20220912214055 -prefsHandle 5984 -prefMapHandle 6132 -prefsLen 31420 -prefMapSize 234361 -appDir "D:\AppData\Firefox\firefox\browser" - {3740db73-7024-47b1-8ae6-d9b9d77a19cf} 2780 "\\.\pipe\gecko-crash-server-pipe.2780" 6080 193b9f44858 rdd"
CallingProcessId 0x00002550
CallingProcessCreateTime 0x01d8d99bc394925a
CallingProcessStartKey 0x050300000000043b
CallingProcessSignatureLevel 0x08
CallingProcessSectionSignatureLevel 0x08
CallingProcessProtection 0x00
CallingThreadId 0x00003df8
CallingThreadCreateTime 0x01d8d99bc394926e
```

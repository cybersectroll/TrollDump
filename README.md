# TrollDump
- Injects x64 managed DLL into x64 managed/unmanaged process (process must have GUI because we obtain its windows handle) using setwindowshook
- Here as a TROLL, we inject into hidden window taskmgr to do a lsass dump *undetected* (see Test Case section below)
- The injector DLL and injected DLL is the same DLL hence no additional DLL required
- Integrity level of target process must be same or lower as injector process 

# Credits (upgrade/rewrite of project) 
Original Project: https://github.com/enkomio/ManagedInjector
  - ported code to inject into 64 bit binaries   ---> original project ony allows dll injection into 32 bit binaries
  - removed IPC logic because it was overbearing 
  - created boilerplate code to just run your payload directly in the RunOnRemoteProcess() function instead of the previous convoluted way
  - project still uses DLLExport to get a .NET DLL to export functions
     - Note this is not a dependency to the project but more of a postprocessing. DLLExport will modify your final .NET DLL to export a function.
     - Can manually do the function exporting if you want https://blog.xpnsec.com/rundll32-your-dotnet/
       
# Compiling  
- Download project & Compile solution as X64, Release 
- No external dependencies needed
 
# Usage 
```
> Requires High Integrity depending on use case
> [System.Reflection.Assembly]::LoadFrom("C:\Users\public\TrollDump.dll")
> [TrollDump.ForFun]::Main("C:\windows\system32\taskmgr.exe")
```
- In this POC, we do a lsass dump, you can run whatever "DLL exported function logic" you want by modifying the function RunOnRemoteProcess() and recompiling.
- As mentioned earlier, the code serves as boilerplate for the dll injection, what you choose to do after is conveniently writable in c# managed code.


# Test Case
- Win 2019 build 17763.737 with latest windefender patches 
  - both dllinject + lsass dump
- Other AVs (unnamed)
  - dllinject works fine
  - obviously whether lsass dump works or not depends if the AV allows taskmgr to dump lsass 
- Not tested on any EDRs -> i suspect the dll injection should still work on specific EDRs

# OPSEC
- DLL needs to be on disk so should be obfuscated
- DLL should only be used to do injection, actual payload should never be embedded into DLL and should be reflectively loaded
- Obviously injecting CLR into unmanaged process is suspicious but hey!
- setwindowshook although a classic technique is most often tied to keylogging, not our use case
- Can be super creative with whichever GUI process you want to inject (if running as system, can inject into dwm.exe as well)

# Wishlist - Project was done over the weekend and I have no time/intent to pursue the following:
- Inject into gui-less process 
  - currently for setwindowshook it uses WH_CALLWNDPROC, you can modify it to use WH_GETMESSAGE but the target process must be running a message loop (GetMessage())
  -  if you can find a non gui binary that implements a message loop (i suspect unlikely) then you can inject into guiless binaries as well
  -  common for GUI processes to run GetMessage()
- Fully reflective and not needed to drop on disk
  - Based on setwindowshook, it seems like the DLL *must be on disk?*
  - i tried to use c# delegates to pass a function pointer to run instead of the exported DLL function and that didnt work (this is the classic c# keylogger technique for local process but we are doing remote process) 
  - you can give this a try by incorporating other techniques, i think its doable
- Taskmgr will automatically spawn as High Integrity even if our current process is Medium (so technically if we inject DLL into it, its a UAC bypass)
  - The injection seems to work fine as per the WIN API return results
  - However, taskmgr fails to call the exported function

# Disclaimer
Should only be used for educational purposes!

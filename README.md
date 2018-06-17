# GetSystem
A basic GetSystem, for Windows 7 and 10 (maybe 8 ?), which has the vocation to become a token forgery. The privilege escalation works from an admin account to the system account. No bypass UAC is featured. The escalation mechanism is the named pipe client impersonation technic with a service connecting to a named pipe called "my_pipe", driven by the program.

Compiles fine on windows 7 in Visual Studio 2015 and on Windows 10 1803 in Visual Studio 2017.
Does not support x64 compilation at the moment.

Use this project at your own risk ! I cannot be held responsible if you break your PC because of this.

Any pull request is welcome, but be informed that this is mainly a test project for security token and memory mapping manipulation. This project is intended to become a token forgery, and a new repo will be created once the base functions are implemented.



# Note about payloads.h:
This is a basic x86 PE printing Hello World then system("pause"). This is used in the experimental functions of PE injection from memory (case 11 and 12 in GetSystem.c) with pfnZwUnmapViewOfSection, VirtualAllocEx and WriteProcessMemory on a suspended process. The base64 payload is decoded at runtime and is written over the view of section of a suspended calc.exe process.

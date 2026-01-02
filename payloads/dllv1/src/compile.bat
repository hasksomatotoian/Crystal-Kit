@ECHO OFF

rc.exe /nologo resource.rc
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /DLL /OUT:..\bin\mscorsvc.dll /MACHINE:x64 resource.res
del *.obj
del resource.res
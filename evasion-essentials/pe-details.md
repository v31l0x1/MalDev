# PE Details

* Version details can be extracted using Resource Hacker and can be reused by implant.
* To add version info for PE in Visual Studio
  * Click on Add Resource, name it anything like ver.rc
  * Now, right-click on the resource and click on Add a Resource.
  * Select Version, once it is expanded, the version and double click the file to edit the version info
* To manually compile it, use&#x20;

```
@ECHO OFF

rc ver.rc
cvtres /MACHINE:x64 /OUT:ver.o ver.res
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcimplant.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 ver.o

del *.obj *.o *.res
```

### ver.rc

```c

1 VERSIONINFO
FILEVERSION 10,0,19041,3636
PRODUCTVERSION 10,0,19041,3636
FILEOS 0x40004
FILETYPE 0x2
{
BLOCK "StringFileInfo"
{
	BLOCK "040904B0"
	{
		VALUE "CompanyName", "Microsoft Corporation"
		VALUE "FileDescription", "Windows NT BASE API Client DLL"
		VALUE "FileVersion", "10.0.19041.3636 (WinBuild.160101.0800)"
		VALUE "InternalName", "kernel32"
		VALUE "LegalCopyright", "\xA9 Microsoft Corporation. All rights reserved."
		VALUE "OriginalFilename", "kernel32"
		VALUE "ProductName", "Microsoft\xAE Windows\xAE Operating System"
		VALUE "ProductVersion", "10.0.19041.3636"
	}
}

BLOCK "VarFileInfo"
{
	VALUE "Translation", 0x0409 0x04B0  
}
}

```

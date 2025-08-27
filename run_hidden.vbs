Set fso = CreateObject("Scripting.FileSystemObject")
folder = fso.GetParentFolderName(WScript.ScriptFullName)
cmd = "cmd /c """ & folder & "\run.bat"""
CreateObject("Wscript.Shell").Run cmd, 0, False

# pe-parse-v2

This is a 32-bit Portable Executable parser project written in C

## How to use

1. Download this repo
1. Compile pe-parse-v2.cpp (Use a C compiler on Windows, it's better if you use Visual Studio's compiler for C++)
1. Run the `.exe` and pass the name of the DLL/EXE as first parameter.
1. ???
1. Profit

### Note

This parser prints the output in Markdown format, so you can redirect the output to a file and then view it rendered.

Ex: 

`C:\> .\pe-parse-v2.exe "C:\Path\To\MyFile.dll" > output.md` 

#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

// Function definition
char* getFileName(int argc, char* argv[]);
FILE* openFile(char fileName[]);
void mapFileToMemory();
int getFileSize(FILE *fp);
char* readFullFile(FILE* fp, int size);
IMAGE_DOS_HEADER* parseDosHeader(char* fileData);
IMAGE_NT_HEADERS32  * parseNtHeaders(char* fileData, int ntHeaderOffset);
void printFileHeader(IMAGE_FILE_HEADER fh);
void printOptionalHeader(IMAGE_OPTIONAL_HEADER32 oh);
void parseSectionHeaders(char* fileData, int sectionHeadersOffset, int numberOfSections);
IMAGE_SECTION_HEADER* getSection(char* fileData, int sectionHeadersOffset, int numberOfSections, int sectionRva);
void parseExportDirectory(unsigned char* fileData, IMAGE_SECTION_HEADER* exportSection, int exportSectionRva);
void parseImportDirectory(char* fileData, IMAGE_SECTION_HEADER* importSection, int importSectionRva);


int main(int argc, char* argv[]) {
    // Get file name
    char* file_name = getFileName(argc, argv);

    // Open the file
    FILE* fp = openFile(file_name);

    // Map file to memory
    // mapFileToMemory();
    
    // Get File size
    int size = getFileSize(fp);
    
    // Read all the file
    char* fileData = readFullFile(fp, size);

    // Parse DOS Headers
    IMAGE_DOS_HEADER* dh = parseDosHeader(fileData);

    // Parse NT Headers
    int ntHeaderOffset = (int)dh->e_lfanew;
    IMAGE_NT_HEADERS32  * nth = parseNtHeaders(fileData, ntHeaderOffset);

    // Print NT Headers -> File Header
    printFileHeader(nth->FileHeader);

    // Print NT Headers -> Optional Header
    printOptionalHeader(nth->OptionalHeader);
    
    // Parse section headers
    int sectionHeadersOffset = (DWORD)ntHeaderOffset + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)nth->FileHeader.SizeOfOptionalHeader;
    int numberOfSections = nth->FileHeader.NumberOfSections;
    parseSectionHeaders(fileData, sectionHeadersOffset, numberOfSections);

    // Get Export Section
    int exportSectionRva = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    IMAGE_SECTION_HEADER* exportSection = getSection(fileData, sectionHeadersOffset, numberOfSections, exportSectionRva);
    printf("Export section at %s (%#0x)\n", exportSection->Name, exportSection->Misc.PhysicalAddress);
    parseExportDirectory((unsigned char*)fileData, exportSection, exportSectionRva);

    // Parse Import Directory
    int importSectionRva = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    IMAGE_SECTION_HEADER* importSection = getSection(fileData, sectionHeadersOffset, numberOfSections, importSectionRva);
    printf("Import section at %s (%#0x)\n", importSection->Name, importSection->Misc.PhysicalAddress);
    parseImportDirectory(fileData, importSection, importSectionRva);

    return 0;
}

char* getFileName(int argc, char* argv[]) {
    if (argc == 1) {
        printf("No file name passed\n");
        exit(0);
    }
    else if (argc > 2) {
        printf("You can only pass one file name\n");
        exit(0);
    }
    else {
        printf("# %s\n", argv[1]);
        return argv[1];
    }
}

FILE* openFile(char fileName[]) {
    printf("\n* Opening file: %s\n", fileName);
    FILE* fp = fopen(fileName, "r");
    if (fp == NULL) {
        printf("\n\t* File Open error. Aborting\n");
        exit(0);
    }
    printf("\n\t* Success! file %s opened at: %#0x\n", fileName, (int)fp);
    return fp;
}

/*void mapFileToMemory() {
    printf("Mapping file %s (%d) to memory\n", fileName, (int)fp);
    fh = CreateFileMappingA(fp, NULL, PAGE_READONLY, 0, 0, "parsed_dll");
    if (fh == NULL) {
        printf("File maping error\nAborting\n");
        exit(0);
    }
    printf("File mapped: %s\t%d\n", fileName, (int)fh);
}*/

int getFileSize(FILE *fp) {
    // Seek end of file
    fseek(fp, 0, SEEK_END);
    // Calculte file size
    long int size = ftell(fp);
    printf("\n\t\t* File size is %d bytes\n", size);
    // Reset file pointer
    rewind(fp);
    return size;
}

char* readFullFile(FILE* fp, int size) {
    printf("\n\t\t* Reading file data to memory\n");
    char* fileData = (char*)malloc(size);
    int readed = fread(fileData, 1, size, fp);
    printf("\n\t\t\t* Success! File data readed to %#0x\n", (int)fileData);
    printf("\n\t\t\t* Parsing...\n");
    return fileData;
}

IMAGE_DOS_HEADER* parseDosHeader(char* fileData) {
    IMAGE_DOS_HEADER* dh = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));
    dh = (IMAGE_DOS_HEADER*)fileData;
    // Printing DOS-HEADER
    printf("\n## DOS-HEADER\n");
    printf("\n| DOS HEADER | |\n");
    printf("| ------- | --: |\n");
    printf("e_magic | %#0x \n", dh->e_magic);
    printf("e_cblp | %#0x \n", dh->e_cblp);
    printf("e_cp | %#0x \n", dh->e_cp);
    printf("e_crlc | %#0x \n", dh->e_crlc);
    printf("e_cparhdr | %#0x \n", dh->e_cparhdr);
    printf("e_minalloc | %#0x \n", dh->e_minalloc);
    printf("e_maxalloc | %#0x \n", dh->e_maxalloc);
    printf("e_ss | %#0x \n", dh->e_ss);
    printf("e_sp | %#0x \n", dh->e_sp);
    printf("e_csum | %#0x \n", dh->e_csum);
    printf("e_ip | %#0x \n", dh->e_ip);
    printf("e_cs | %#0x \n", dh->e_cs);
    printf("e_lfarlc | %#0x \n", dh->e_lfarlc);
    printf("e_ovno | %#0x \n", dh->e_ovno);
    printf("e_res | %#0x \n", *dh->e_res); //array
    printf("e_oemid | %#0x \n", dh->e_oemid);
    printf("e_oeminfo | %#0x \n", dh->e_oeminfo);
    printf("e_res2 | %#0x \n", *dh->e_res2); //array
    printf("e_lfanew | %#0x \n", dh->e_lfanew);
    printf("\n");
    return dh;
}

IMAGE_NT_HEADERS32  * parseNtHeaders(char* fileData, int ntHeaderOffset) {
    IMAGE_NT_HEADERS32  * nth = (IMAGE_NT_HEADERS32  *)malloc(sizeof(IMAGE_NT_HEADERS32));
    nth = (IMAGE_NT_HEADERS32  *) &fileData[ntHeaderOffset];
    printf("\n## NT-HEADERS\n");
    printf("\n| NT-HEADERS | |\n");
    printf("| --------- | --: |\n");
    printf(" Signature | %#0x\n", nth->Signature);
    printf("\n");
    return nth;
}

void printFileHeader(IMAGE_FILE_HEADER fh) {
    printf("\n| FILE-HEADER | |\n");
    printf("| --------- | --: |\n");
    printf("machine | %#0x\n", fh.Machine);
    printf("number_of_sections | %#0x\n", fh.NumberOfSections);
    printf("time_date_stamp | %#0x\n", fh.TimeDateStamp);
    printf("pointer_to_symbol_table | %#0x\n", fh.PointerToSymbolTable);
    printf("number_of_symbols | %#0x\n", fh.NumberOfSymbols);
    printf("size_of_optional_header | %#0x\n", fh.SizeOfOptionalHeader);
    printf("characteristics | %#0x\n", fh.Characteristics);
}

void printOptionalHeader(IMAGE_OPTIONAL_HEADER32 oh) {
    printf("\n| OPTIONAL-HEADER | |\n");
    printf("| --------- | --: |\n");
    printf("Magic | %#0x\n", oh.Magic);
    printf("MajorLinkerVersion | %#0x\n", oh.MajorLinkerVersion);
    printf("MinorLinkerVersion | %#0x\n", oh.MinorLinkerVersion);
    printf("SizeOfCode | %#0x\n", oh.SizeOfCode);
    printf("SizeOfInitializedData | %#0x\n", oh.SizeOfInitializedData);
    printf("SizeOfUninitializedData | %#0x\n", oh.SizeOfUninitializedData);
    printf("AddressOfEntryPoint | %#0x\n", oh.AddressOfEntryPoint);
    printf("BaseOfCode | %#0x\n", oh.BaseOfCode);
    printf("BaseOfData | %#0x\n", oh.BaseOfData);
    printf("ImageBase | %#0x\n", oh.ImageBase);
    printf("SectionAlignment | %#0x\n", oh.SectionAlignment);
    printf("FileAlignment | %#0x\n", oh.FileAlignment);
    printf("MajorOperatingSystemVersion | %#0x\n", oh.MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion | %#0x\n", oh.MinorOperatingSystemVersion);
    printf("MajorImageVersion | %#0x\n", oh.MajorImageVersion);
    printf("MinorImageVersion | %#0x\n", oh.MinorImageVersion);
    printf("MajorSubsystemVersion | %#0x\n", oh.MajorSubsystemVersion);
    printf("MinorSubsystemVersion | %#0x\n", oh.MinorSubsystemVersion);
    printf("Win32VersionValue | %#0x\n", oh.Win32VersionValue);
    printf("SizeOfImage | %#0x\n", oh.SizeOfImage);
    printf("SizeOfHeaders | %#0x\n", oh.SizeOfHeaders);
    printf("CheckSum | %#0x\n", oh.CheckSum);
    printf("Subsystem | %#0x\n", oh.Subsystem);
    printf("DllCharacteristics | %#0x\n", oh.DllCharacteristics);
    printf("SizeOfStackReserve | %#0x\n", oh.SizeOfStackReserve);
    printf("SizeOfStackCommit | %#0x\n", oh.SizeOfStackCommit);
    printf("SizeOfHeapReserve | %#0x\n", oh.SizeOfHeapReserve);
    printf("SizeOfHeapCommit | %#0x\n", oh.SizeOfHeapCommit);
    printf("LoaderFlags | %#0x\n", oh.LoaderFlags);
    printf("NumberOfRvaAndSizes | %#0x\n", oh.NumberOfRvaAndSizes);

    printf("\n### DATA-DIRECTORIES\n");
    printf("\n| N | Virtual Address | Size |\n");
    printf("| --------- | -- | -- |\n");
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        IMAGE_DATA_DIRECTORY idd = oh.DataDirectory[i];
        printf(" %d | %#0x | %#0x\n", i, idd.VirtualAddress, idd.Size);
    }

}

void parseSectionHeaders(char* fileData, int sectionHeadersOffset, int numberOfSections) {
    printf("\n## SECTION-HEADERS\n");
    IMAGE_SECTION_HEADER* sh = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
    
    for (int i = 0; i < numberOfSections; i++) {
        sh = (IMAGE_SECTION_HEADER*)&fileData[sectionHeadersOffset];
        printf("\n| %s | |\n", sh->Name);
        printf("| --------- | --: |\n");
        printf("Virtual Size | %#0x\n", sh->Misc.VirtualSize);
        printf("Virtual Address | %#0x\n", sh->VirtualAddress);
        printf("Size Of Raw Data | %#0x\n", sh->SizeOfRawData);
        printf("Pointer To Raw Data | %#0x\n", sh->PointerToRawData);
        printf("Pointer To Relocations | %#0x\n", sh->PointerToRelocations);
        printf("Pointer To Line Numbers | %#0x\n", sh->PointerToLinenumbers);
        printf("Number Of Relocations | %#0x\n", sh->NumberOfRelocations);
        printf("Number Of Line Numbers | %#0x\n", sh->NumberOfLinenumbers);
        printf("Characteristics | %#0x\n", sh->Characteristics);
        printf("\n");
        sectionHeadersOffset = sectionHeadersOffset + (int)sizeof(IMAGE_SECTION_HEADER);
    }
}

IMAGE_SECTION_HEADER* getSection(char* fileData, int sectionHeadersOffset, int numberOfSections, int sectionRva) {
    IMAGE_SECTION_HEADER* sh = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
    for (int i = 0; i < numberOfSections; i++) {
        sh = (IMAGE_SECTION_HEADER*)&fileData[sectionHeadersOffset];
        if (sectionRva >= sh->VirtualAddress && sectionRva < sh->VirtualAddress + sh->Misc.VirtualSize) {
            return sh;
        }
        sectionHeadersOffset = sectionHeadersOffset + (int)sizeof(IMAGE_SECTION_HEADER);
    }
    return NULL;
}

void parseImportDirectory(char* fileData, IMAGE_SECTION_HEADER* importSection, int importSectionRva) {
    int rawOffset = (int)fileData + importSection->PointerToRawData;
    IMAGE_IMPORT_DESCRIPTOR* importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(rawOffset + (importSectionRva - importSection->VirtualAddress));
    printf("## DLL-IMPORTS\n");
    for (; importDescriptor->Name != 0; importDescriptor++) {
        printf("\n| %s | |\n", rawOffset + (importDescriptor->Name - importSection->VirtualAddress)); // DLL Name
        printf("| -- | --: |\n");

        int thunk;
        if (importDescriptor->OriginalFirstThunk == 0) {
            thunk = importDescriptor->FirstThunk;
        }
        else {
            thunk = importDescriptor->OriginalFirstThunk;
        }
        IMAGE_THUNK_DATA32* thunkData = (IMAGE_THUNK_DATA32*)(rawOffset + (thunk - importSection->VirtualAddress));
        // DLL Functions used by this PE
        for (; thunkData->u1.AddressOfData != 0; thunkData++) {
            if (thunkData->u1.AddressOfData > 0x80000000) {
                printf("| Ordinal | %#0x |\n", (WORD)thunkData->u1.AddressOfData);
            }
            else {
                printf("| %s | |\n", (rawOffset + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2)));
            }
        }
    }
}

void parseExportDirectory(unsigned char* fileData, IMAGE_SECTION_HEADER* exportSection, int exportSectionRva) {
    int rawOffset = (int)fileData + exportSection->PointerToRawData;
    printf("\n%p\n", exportSection->VirtualAddress);
    printf("\n%p\n", exportSection->PointerToRawData);
    IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)(rawOffset + (exportSectionRva - exportSection->VirtualAddress)); // Desplazamiento dentro del section header
    printf("\n## DLL-EXPORTS\n");
    printf("\n| DLL-EXPORTS | |\n");
    printf("| -- | --: |\n");
    printf("Characteristics | %#0x\n", exportDirectory->Characteristics);
    printf("TimeDateStamp | %#0x\n", exportDirectory->TimeDateStamp);
    printf("MajorVersion | %#0x\n", exportDirectory->MajorVersion);
    printf("MinorVersion | %#0x\n", exportDirectory->MinorVersion);
    printf("Name | %#0x\n", exportDirectory->Name);
    printf("Base | %#0x\n", exportDirectory->Base);
    printf("NumberOfFunctions | %#0x\n", exportDirectory->NumberOfFunctions);
    printf("NumberOfNames | %#0x\n", exportDirectory->NumberOfNames);
    printf("AddressOfFunctions | %#0x\n", exportDirectory->AddressOfFunctions);
    printf("AddressOfNames | %#0x\n", exportDirectory->AddressOfNames);
    printf("AddressOfNameOrdinals | %#0x\n", exportDirectory->AddressOfNameOrdinals);
    
    printf("\n### Exported functions\n");

    INT64 firstFunctionAddress = ((INT64)exportDirectory->AddressOfFunctions - (INT64)exportSection->VirtualAddress) + (INT64)exportSection->PointerToRawData;
    INT64 firstFunctionOrdinal = ((INT64)exportDirectory->AddressOfNameOrdinals - (INT64)exportSection->VirtualAddress) + (INT64)exportSection->PointerToRawData;
    INT64 firstFunctionNameRvaAddress = ((INT64)exportDirectory->AddressOfNames - (INT64)exportSection->VirtualAddress) + (INT64)exportSection->PointerToRawData;
    
    INT64 nextFunctionAddress = firstFunctionAddress;
    INT64 nextFunctionOrdinal = firstFunctionOrdinal;
    INT64 nextFunctionNameRvaAddress = firstFunctionNameRvaAddress;
    int nextFunctionNameRva = *(int*)&fileData[nextFunctionNameRvaAddress];
    INT64 nextFunctionNameOffset = (INT64)exportSection->VirtualAddress - (INT64)exportSection->PointerToRawData;
    INT64 nextFunctionNameAddress = (INT64)nextFunctionNameRva - nextFunctionNameOffset;
    //printf("\nnameOffset: %p\n", functionNameOffset);
    //printf("\nexportSection->VirtualAddress: %p\n", exportSection->VirtualAddress);
    //printf("\nexportSection->PointerToRawData: %p\n", exportSection->PointerToRawData);
    printf("\n First function name address %x (%x)\n", (int)fileData[nextFunctionNameRva], (int)nextFunctionNameRva);
    printf("\n# First function Name %s (%x)\n", (char*)((int)fileData + (int)nextFunctionNameAddress), (int)nextFunctionNameAddress);
    printf("\n| Ord | Address | Name |\n");
    printf("| -- | --: | -- |\n");
    for (int i = 0; i < exportDirectory->NumberOfFunctions; i++) {
        //printf("\na is: %p\n", *(int*)(fileData + firstFunctionAddress));
        //printf("\nFunction ordinal at %p -> %p\n", (int) nextFunctionOrdinal, *(WORD*)&fileData[nextFunctionOrdinal]);
        //printf("\nFunction %d at %p -> %p\n",i, (int) nextFunctionAddress, *(int*)&fileData[nextFunctionAddress]);
        WORD functionOrdinal = *(WORD*)&fileData[nextFunctionOrdinal];
        int functionAddress = *(int*)&fileData[nextFunctionAddress];
        printf("%d (%x) | %x (%x) | %s (%x)\n", functionOrdinal, (int)nextFunctionOrdinal, functionAddress, (int)nextFunctionAddress, (char*)((int)fileData + (int)nextFunctionNameAddress), (int)nextFunctionNameAddress);
        
        nextFunctionOrdinal = nextFunctionOrdinal + sizeof(WORD);
        nextFunctionAddress = nextFunctionAddress + sizeof(DWORD);
        nextFunctionNameRvaAddress = nextFunctionNameRvaAddress + sizeof(DWORD);
        nextFunctionNameRva = *(int*)&fileData[nextFunctionNameRvaAddress];
        nextFunctionNameOffset = (INT64)exportSection->VirtualAddress - (INT64)exportSection->PointerToRawData;
        nextFunctionNameAddress = (INT64)nextFunctionNameRva - nextFunctionNameOffset;
    }
    getchar();

}


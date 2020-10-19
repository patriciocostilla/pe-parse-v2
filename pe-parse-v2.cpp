#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

// Variable definition
char file_name[255];
FILE* fp;
HANDLE fh;

// Function definition
void getFileName();
void openFile();
void mapFileToMemory();
int getFileSize(FILE *fp);
char* readFullFile(FILE* fp, int size);
IMAGE_DOS_HEADER* parseDosHeader(char* fileData);
IMAGE_NT_HEADERS32  * parseNtHeaders(char* fileData, int ntHeaderOffset);
/*
* We don't need this, since we have access to file and optional headers via NT-HEADERS
IMAGE_FILE_HEADER* parseFileHeader(char* fileData, int fileHeaderOffset);
*/
void printFileHeader(IMAGE_FILE_HEADER fh);
void printOptionalHeader(IMAGE_OPTIONAL_HEADER32 oh);
void parseSectionHeaders(char* fileData, int sectionHeadersOffset, int numberOfSections);
IMAGE_SECTION_HEADER* getSection(char* fileData, int sectionHeadersOffset, int numberOfSections, int sectionRva);
void parseExportDirectory(char* fileData, IMAGE_SECTION_HEADER* exportSection, int exportSectionRva);
void parseImportDirectory(char* fileData, IMAGE_SECTION_HEADER* importSection, int importSectionRva);


int main() {
    // Get file name
    getFileName();

    // Open the file
    openFile();

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
    
    /*
    * We don't need this, since we have access to file and optional headers via NT-HEADERS
    // Parse NT Headers -> File Header
    //int fileHeaderOffset = (int)(ntHeaderOffset + sizeof(dh->e_lfanew));
    //IMAGE_FILE_HEADER* fh = parseFileHeader(fileData, fileHeaderOffset);
    */

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
    printf("Export section at %s (%x)\n", exportSection->Name, exportSection->Misc.PhysicalAddress);
    parseExportDirectory(fileData, exportSection, exportSectionRva);

    // Parse Import Directory
    int importSectionRva = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    IMAGE_SECTION_HEADER* importSection = getSection(fileData, sectionHeadersOffset, numberOfSections, importSectionRva);
    printf("Import section at %s (%x)\n", importSection->Name, importSection->Misc.PhysicalAddress);
    parseImportDirectory(fileData, importSection, importSectionRva);

    return 0;
}

void getFileName() {
    printf("Enter file name: ");
    fgets(file_name, sizeof(file_name), stdin);
    int i, length;
    length = strlen(file_name);
    for (i = 0; i < length; i++)
    {
        if (file_name[i] == '\n')
            file_name[i] = '\0';
    }
    printf("File name is %s\n", file_name);
}

void openFile() {
    printf("Openign file: %s\n", file_name);
    fp = fopen(file_name, "r");
    if (fp == NULL) {
        printf("File Open error\nAborting\n");
        exit(0);
    }
    printf("File opened: %s\t%x\n", file_name, (int)fp);
}

void mapFileToMemory() {
    printf("Mapping file %s (%d) to memory\n", file_name, (int)fp);
    fh = CreateFileMappingA(fp, NULL, PAGE_READONLY, 0, 0, "parsed_dll");
    if (fh == NULL) {
        printf("File maping error\nAborting\n");
        exit(0);
    }
    printf("File mapped: %s\t%d\n", file_name, (int)fh);
}

int getFileSize(FILE *fp) {
    // Seek end of file
    fseek(fp, 0, SEEK_END);
    // Calculte file size
    long int size = ftell(fp);
    printf("File size is %d bytes\n", size);
    // Reset file pointer
    rewind(fp);
    return size;
}

char* readFullFile(FILE* fp, int size) {
    printf("Reading file data to memory\n");
    char* fileData = (char*)malloc(size);
    int readed = fread(fileData, 1, size, fp);
    printf("File data readed to %x\n", (int)fileData);
    return fileData;
}

IMAGE_DOS_HEADER* parseDosHeader(char* fileData) {
    IMAGE_DOS_HEADER* dh = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));
    dh = (IMAGE_DOS_HEADER*)fileData;
    // Printing DOS-HEADER
    printf("[DOS-HEADER]\n");
    printf("e_magic: %x\n", dh->e_magic);
    printf("e_cblp: %x\n", dh->e_cblp);
    printf("e_cp: %x\n", dh->e_cp);
    printf("e_crlc: %x\n", dh->e_crlc);
    printf("e_cparhdr: %x\n", dh->e_cparhdr);
    printf("e_minalloc: %x\n", dh->e_minalloc);
    printf("e_maxalloc: %x\n", dh->e_maxalloc);
    printf("e_ss: %x\n", dh->e_ss);
    printf("e_sp: %x\n", dh->e_sp);
    printf("e_csum: %x\n", dh->e_csum);
    printf("e_ip: %x\n", dh->e_ip);
    printf("e_cs: %x\n", dh->e_cs);
    printf("e_lfarlc: %x\n", dh->e_lfarlc);
    printf("e_ovno: %x\n", dh->e_ovno);
    printf("e_res: %x\n", *dh->e_res); //array
    printf("e_oemid: %x\n", dh->e_oemid);
    printf("e_oeminfo: %x\n", dh->e_oeminfo);
    printf("e_res2: %x\n", *dh->e_res2); //array
    printf("e_lfanew: %x\n", dh->e_lfanew);
    printf("\n");
    return dh;
}

IMAGE_NT_HEADERS32  * parseNtHeaders(char* fileData, int ntHeaderOffset) {
    IMAGE_NT_HEADERS32  * nth = (IMAGE_NT_HEADERS32  *)malloc(sizeof(IMAGE_NT_HEADERS32));
    nth = (IMAGE_NT_HEADERS32  *) &fileData[ntHeaderOffset];
    printf("[NT-HEADERS]\n");
    printf("Signature: %x\n", nth->Signature);
    printf("\n");
    return nth;
}
/*
IMAGE_FILE_HEADER* parseFileHeader(char* fileData, int fileHeaderOffset) {
    IMAGE_FILE_HEADER* fh = (IMAGE_FILE_HEADER*)malloc(sizeof(IMAGE_FILE_HEADER));
    fh = (IMAGE_FILE_HEADER*)&fileData[fileHeaderOffset];
    printf("[FILE-HEADER]\n");
    printf("machine: %x\n", fh->Machine);
    printf("number_of_sections: %x\n", fh->NumberOfSections);
    printf("time_date_stamp: %x\n", fh->TimeDateStamp);
    printf("pointer_to_symbol_table: %x\n", fh->PointerToSymbolTable);
    printf("number_of_symbols: %x\n", fh->NumberOfSymbols);
    printf("size_of_optional_header: %x\n", fh->SizeOfOptionalHeader);
    printf("characteristics: %x\n", fh->Characteristics);
    return fh;
}
*/

void printFileHeader(IMAGE_FILE_HEADER fh) {
    printf("[FILE-HEADER]\n");
    printf("machine: %x\n", fh.Machine);
    printf("number_of_sections: %x\n", fh.NumberOfSections);
    printf("time_date_stamp: %x\n", fh.TimeDateStamp);
    printf("pointer_to_symbol_table: %x\n", fh.PointerToSymbolTable);
    printf("number_of_symbols: %x\n", fh.NumberOfSymbols);
    printf("size_of_optional_header: %x\n", fh.SizeOfOptionalHeader);
    printf("characteristics: %x\n", fh.Characteristics);
}

void printOptionalHeader(IMAGE_OPTIONAL_HEADER32 oh) {
    printf("[OPTIONAL-HEADER]");
    printf("Magic: %x\n", oh.Magic);
    printf("MajorLinkerVersion: %x\n", oh.MajorLinkerVersion);
    printf("MinorLinkerVersion: %x\n", oh.MinorLinkerVersion);
    printf("SizeOfCode: %x\n", oh.SizeOfCode);
    printf("SizeOfInitializedData: %x\n", oh.SizeOfInitializedData);
    printf("SizeOfUninitializedData: %x\n", oh.SizeOfUninitializedData);
    printf("AddressOfEntryPoint: %x\n", oh.AddressOfEntryPoint);
    printf("BaseOfCode: %x\n", oh.BaseOfCode);
    printf("BaseOfData: %x\n", oh.BaseOfData);
    printf("ImageBase: %x\n", oh.ImageBase);
    printf("SectionAlignment: %x\n", oh.SectionAlignment);
    printf("FileAlignment: %x\n", oh.FileAlignment);
    printf("MajorOperatingSystemVersion: %x\n", oh.MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion: %x\n", oh.MinorOperatingSystemVersion);
    printf("MajorImageVersion: %x\n", oh.MajorImageVersion);
    printf("MinorImageVersion: %x\n", oh.MinorImageVersion);
    printf("MajorSubsystemVersion: %x\n", oh.MajorSubsystemVersion);
    printf("MinorSubsystemVersion: %x\n", oh.MinorSubsystemVersion);
    printf("Win32VersionValue: %x\n", oh.Win32VersionValue);
    printf("SizeOfImage: %x\n", oh.SizeOfImage);
    printf("SizeOfHeaders: %x\n", oh.SizeOfHeaders);
    printf("CheckSum: %x\n", oh.CheckSum);
    printf("Subsystem: %x\n", oh.Subsystem);
    printf("DllCharacteristics: %x\n", oh.DllCharacteristics);
    printf("SizeOfStackReserve: %x\n", oh.SizeOfStackReserve);
    printf("SizeOfStackCommit: %x\n", oh.SizeOfStackCommit);
    printf("SizeOfHeapReserve: %x\n", oh.SizeOfHeapReserve);
    printf("SizeOfHeapCommit: %x\n", oh.SizeOfHeapCommit);
    printf("LoaderFlags: %x\n", oh.LoaderFlags);
    printf("NumberOfRvaAndSizes: %x\n", oh.NumberOfRvaAndSizes);

    printf("[OPTIONAL-HEADER->data-directory]\n");
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        IMAGE_DATA_DIRECTORY idd = oh.DataDirectory[i];
        printf("\t[%d]\n", i);
        printf("\t - VirtualAddress: %x\n", idd.VirtualAddress);
        printf("\t - Size: %x\n", idd.Size);
    }

}

void parseSectionHeaders(char* fileData, int sectionHeadersOffset, int numberOfSections) {
    printf("[SECTION-HEADERS]\n");
    IMAGE_SECTION_HEADER* sh = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
    
    for (int i = 0; i < numberOfSections; i++) {
        sh = (IMAGE_SECTION_HEADER*)&fileData[sectionHeadersOffset];
        printf("%s\n", sh->Name);
        printf("\tVirtual Size: %x\n", sh->Misc.VirtualSize);
        printf("\tVirtual Address: %x\n", sh->VirtualAddress);
        printf("\tSize Of Raw Data: %x\n", sh->SizeOfRawData);
        printf("\tPointer To Raw Data: %x\n", sh->PointerToRawData);
        printf("\tPointer To Relocations: %x\n", sh->PointerToRelocations);
        printf("\tPointer To Line Numbers: %x\n", sh->PointerToLinenumbers);
        printf("\tNumber Of Relocations: %x\n", sh->NumberOfRelocations);
        printf("\tNumber Of Line Numbers: %x\n", sh->NumberOfLinenumbers);
        printf("\tCharacteristics: %x\n", sh->Characteristics);
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
    printf("[DLL-IMPORTS]\n");
    for (; importDescriptor->Name != 0; importDescriptor++) {
        printf("\t%s\n", rawOffset + (importDescriptor->Name - importSection->VirtualAddress)); // DLL Name
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
                printf("\t\tOrdinal: %x\n", (WORD)thunkData->u1.AddressOfData);
            }
            else {
                printf("\t\t%s\n", (rawOffset + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2)));
            }
        }
    }
}

void parseExportDirectory(char* fileData, IMAGE_SECTION_HEADER* exportSection, int exportSectionRva) {
    int rawOffset = (int)fileData + exportSection->PointerToRawData;
    IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)(rawOffset + (exportSectionRva - exportSection->VirtualAddress));
    printf("[DLL-EXPORTS]\n");
    printf("\tCharacteristics: %x\n", exportDirectory->Characteristics);
    printf("\tTimeDateStamp: %x\n", exportDirectory->TimeDateStamp);
    printf("\tMajorVersion: %x\n", exportDirectory->MajorVersion);
    printf("\tMinorVersion: %x\n", exportDirectory->MinorVersion);
    printf("\tName: %x\n", exportDirectory->Name);
    printf("\tBase: %x\n", exportDirectory->Base);
    printf("\tNumberOfFunctions: %x\n", exportDirectory->NumberOfFunctions);
    printf("\tNumberOfNames: %x\n", exportDirectory->NumberOfNames);
    printf("\tAddressOfFunctions: %x\n", exportDirectory->AddressOfFunctions);
    printf("\tAddressOfNames: %x\n", exportDirectory->AddressOfNames);
    printf("\tAddressOfNameOrdinals: %x\n", exportDirectory->AddressOfNameOrdinals);

    int firstOffset = (int)fileData + exportDirectory->AddressOfFunctions;
    printf("\n%x\n", (unsigned long) fileData[exportDirectory->AddressOfFunctions]);

}
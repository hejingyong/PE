
# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"

/*
1.通过编写控制台程序，将一个EXE文件读取到内存，打印出它所有的文件信息。(与LordPE的结果进行对照)
*/


int PrintPEDosHeader(PVOID pFileAddress)
{
	int ret = 0;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileAddress;


	printf("****************DOS_Header STAR*************************\n");
    printf("Dos->e_magic        :%02X\n", pDosHeader->e_magic);
    printf("Dos->e_cblp         :%02X\n", pDosHeader->e_cblp);
    printf("Dos->e_cp           :%02X\n", pDosHeader->e_cp);
    printf("Dos->e_crlc         :%02X\n", pDosHeader->e_crlc);
    printf("Dos->e_aparhdr      :%02X\n", pDosHeader->e_cparhdr);
    printf("Dos->e_minalloc     :%02X\n", pDosHeader->e_minalloc);
    printf("Dos->e_maxalloc     :%02X\n", pDosHeader->e_maxalloc);
    printf("Dos->e_ss           :%02X\n", pDosHeader->e_ss);
    printf("Dos->e_sp           :%02X\n", pDosHeader->e_sp);
    printf("Dos->e_csum         :%02X\n", pDosHeader->e_csum);
    printf("Dos->e_ip           :%02X\n", pDosHeader->e_ip);
    printf("Dos->e_cs           :%02X\n", pDosHeader->e_cs);
    printf("Dos->e_lfarlc       :%02X\n", pDosHeader->e_lfarlc);
    printf("Dos->e_ovno         :%02X\n", pDosHeader->e_ovno);
    for (int i = 0; i < 4; i++)
    {
		printf("Dos->e_res[%d]       :%02X\n", i, pDosHeader->e_res[i]);
    }
    printf("Dos->e_oeminfo      :%02X\n", pDosHeader->e_oeminfo);
    for (int i = 0; i < 10; i++)
    {
        printf("Dos->e_res2[%d]      :%02X\n", i, pDosHeader->e_res2[i]);
    }
    printf("Dos->e_lfanew       :%04X\n", pDosHeader->e_lfanew);
	printf("*****************DOS_Header END************************\n");

	return ret;
}

int PrintPEFileHeader(PVOID pFileAddress)
{
	int ret = 0;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileAddress;
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew + 4);

	printf("****************FILE_HEADER STAR*************************\n");
	printf("FileHeader->Machine              : %02X\n", pFileHeader->Machine);
	printf("FileHeader->NumberOfSections     : %02X\n", pFileHeader->NumberOfSections);
	printf("FileHeader->TimeDateStamp        : %04X\n", pFileHeader->TimeDateStamp);
	printf("FileHeader->PointerToSymbolTable : %04X\n", pFileHeader->PointerToSymbolTable);
	printf("FileHeader->NumberOfSymbols      : %04X\n", pFileHeader->NumberOfSymbols);
	printf("FileHeader->SizeOfOptionalHeader : %02X\n", pFileHeader->SizeOfOptionalHeader);
	printf("FileHeader->Characteristics      : %02X\n", pFileHeader->Characteristics);

	printf("*****************FILE_HEADER END************************\n");

	return ret;
}

int PrintPEOptionalHeader(PVOID pFileAddress)
{
	int ret = 0;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileAddress;
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));


	printf("****************OPTIONAL_HEADER32 STAR*************************\n");
	printf("OptionalHeader->Magic                        : %02X\n", pOptionalHeader->Magic);
	printf("OptionalHeader->MajorLinkerVersion           : %01X\n", pOptionalHeader->MajorLinkerVersion);
	printf("OptionalHeader->MinorLinkerVersion           : %01X\n", pOptionalHeader->MinorLinkerVersion);
	printf("OptionalHeader->SizeOfCode                   : %04X\n", pOptionalHeader->SizeOfCode);
	printf("OptionalHeader->SizeOfInitializedData        : %04X\n", pOptionalHeader->SizeOfInitializedData);
	printf("OptionalHeader->SizeOfUninitializedData      : %04X\n", pOptionalHeader->SizeOfUninitializedData);
	printf("OptionalHeader->AddressOfEntryPoint          : %04X\n", pOptionalHeader->AddressOfEntryPoint);
	printf("OptionalHeader->BaseOfCode                   : %04X\n", pOptionalHeader->BaseOfCode);
	printf("OptionalHeader->BaseOfData                   : %04X\n", pOptionalHeader->BaseOfData);
	printf("OptionalHeader->ImageBase                    : %04X\n", pOptionalHeader->ImageBase);
	printf("OptionalHeader->SectionAlignment             : %04X\n", pOptionalHeader->SectionAlignment);
	printf("OptionalHeader->FileAlignment                : %04X\n", pOptionalHeader->FileAlignment);
	printf("OptionalHeader->MajorOperatingSystemVersion  : %02X\n", pOptionalHeader->MajorOperatingSystemVersion);
	printf("OptionalHeader->MinorOperatingSystemVersion  : %02X\n", pOptionalHeader->MinorOperatingSystemVersion);
	printf("OptionalHeader->MajorImageVersion            : %02X\n", pOptionalHeader->MajorImageVersion);
	printf("OptionalHeader->MinorImageVersion            : %02X\n", pOptionalHeader->MinorImageVersion);
	printf("OptionalHeader->MajorSubsystemVersion        : %02X\n", pOptionalHeader->MajorSubsystemVersion);
	printf("OptionalHeader->MinorSubsystemVersion        : %02X\n", pOptionalHeader->MinorSubsystemVersion);
	printf("OptionalHeader->Win32VersionValue            : %04X\n", pOptionalHeader->Win32VersionValue);
	printf("OptionalHeader->SizeOfImage                  : %04X\n", pOptionalHeader->SizeOfImage);
	printf("OptionalHeader->SizeOfHeaders                : %04X\n", pOptionalHeader->SizeOfHeaders);
	printf("OptionalHeader->CheckSum                     : %04X\n", pOptionalHeader->CheckSum);
	printf("OptionalHeader->Subsystem                    : %02X\n", pOptionalHeader->Subsystem);
	printf("OptionalHeader->DllCharacteristics           : %02X\n", pOptionalHeader->DllCharacteristics);
	printf("OptionalHeader->SizeOfStackReserv            : %04X\n", pOptionalHeader->SizeOfStackReserve);
	printf("OptionalHeader->SizeOfStackCommit            : %04X\n", pOptionalHeader->SizeOfStackCommit);
	printf("OptionalHeader->SizeOfHeapReserve            : %04X\n", pOptionalHeader->SizeOfHeapReserve);
	printf("OptionalHeader->SizeOfHeapCommit             : %04X\n", pOptionalHeader->SizeOfHeapCommit);
	printf("OptionalHeader->LoaderFlags                  : %04X\n", pOptionalHeader->LoaderFlags);
	printf("OptionalHeader->NumberOfRvaAndSizes          : %04X\n", pOptionalHeader->NumberOfRvaAndSizes);

	printf("*****************OPTIONAL_HEADER32 END************************\n");

	return ret;
}

int PrintPESectionHeader(PVOID pFileAddress)
{
	int ret = 0;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileAddress;
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

	printf("****************SECTION_HEADER STAR*************************\n");
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		printf("pSectionGroup[%d].Name                   : %s\n", i, pSectionGroup[i].Name);
		printf("pSectionGroup[%d].Misc.VirtualSize       : %04X\n", i, pSectionGroup[i].Misc.VirtualSize);
		printf("pSectionGroup[%d].VirtualAddress         : %04X\n", i, pSectionGroup[i].VirtualAddress);
		printf("pSectionGroup[%d].SizeOfRawData          : %04X\n", i, pSectionGroup[i].SizeOfRawData);
		printf("pSectionGroup[%d].PointerToRawData       : %04X\n", i, pSectionGroup[i].PointerToRawData);
		printf("pSectionGroup[%d].PointerToRelocations   : %04X\n", i, pSectionGroup[i].PointerToRelocations);
		printf("pSectionGroup[%d].PointerToLinenumbers   : %04X\n", i, pSectionGroup[i].PointerToLinenumbers);
		printf("pSectionGroup[%d].NumberOfRelocations    : %02X\n", i, pSectionGroup[i].NumberOfRelocations);
		printf("pSectionGroup[%d].NumberOfLinenumbers    : %02X\n", i, pSectionGroup[i].NumberOfLinenumbers);
		printf("pSectionGroup[%d].Characteristics        : %04X\n\n\n", i, pSectionGroup[i].Characteristics);
	}

	printf("*****************SECTION_HEADER END************************\n");

	return ret;
}

int main()
{
	int ret = 0;

	PVOID pFileAddress = NULL;
	
	//1、加载PE文件进入内存
	ret = MyReadFile(&pFileAddress);
	if (ret != 0)
	{
		return ret;
	}
	printf("将文件载入内存成功！。。。。。\n");

	//2、打印PE信息
	ret = PrintPEDosHeader(pFileAddress);//DOS头
	if (ret != 0)
	{
		if (pFileAddress != NULL)
		{
			free(pFileAddress);
		}
		return ret;
	}
	ret = PrintPEFileHeader(pFileAddress);//FileHeader
	if (ret != 0)
	{
		if (pFileAddress != NULL)
		{
			free(pFileAddress);
		}
		return ret;
	}
	ret = PrintPEOptionalHeader(pFileAddress);//OptionalHeader
	if (ret != 0)
	{
		if (pFileAddress != NULL)
		{
			free(pFileAddress);
		}
		return ret;
	}
	ret = PrintPESectionHeader(pFileAddress);//SectionHeader
	if (ret != 0)
	{
		if (pFileAddress != NULL)
		{
			free(pFileAddress);
		}
		return ret;
	}

	if (pFileAddress != NULL)
	{
		free(pFileAddress);
	}

	system("pause");

	PrintReloactionTable();
	return ret;
}

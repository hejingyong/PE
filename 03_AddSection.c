# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"

# define NEW_FILE "C:/Users/Qiu_JY/Desktop/Out.exe"


/*
3.通过编写控制台程序，将一个EXE文件读取到内存，在它的节表中新增一个节表和节区，存盘后让他可以正常运行。
*/

//添加节的主要操作
int AddSection(PVOID FileAddress, PVOID *NewFileAddress, PDWORD pNewLength)
{
	int ret = 0;

	DWORD OldLength = 0;
	DWORD NewLength = 0;
	DWORD RemainingSpace = 0;	//	剩余空间
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionGroup = NULL;
	PIMAGE_SECTION_HEADER pLastSection = NULL;

	//1、进行扩展空间
	FILE *pf = fopen(FILE_PATH, "rb");
	if (pf == NULL)
	{
		ret = -1;
		printf("func fopen() Error: %d\n", ret);
		return ret;
	}
	ret = GetFileLength(pf, &OldLength);
	if (ret != 0 && OldLength == -1)
	{
		ret = -2;
		printf("func GetFileLength() Error!\n");
		return ret;
	}

	//将旧的空间增加0x1000
	NewLength = OldLength + 0x1000;
	*NewFileAddress = (LPVOID)malloc(NewLength);
	if (*NewFileAddress == NULL)
	{
		ret = -3;
		printf("func malloc() Error!\n");
		return ret;
	}
	memset(*NewFileAddress, 0, NewLength);

	//2、将旧空间的内容copy到新的空间
	memcpy(*NewFileAddress, FileAddress, OldLength);

	//3、将指针指向对应位置
	pDosHeader		= (PIMAGE_DOS_HEADER)(*NewFileAddress);
	pFileHeader		= (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionGroup	= (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	pLastSection	= &pSectionGroup[pFileHeader->NumberOfSections - 1];

	//4、判断是否有足够的内存空间
	RemainingSpace =	pOptionalHeader->SizeOfHeaders - 
						pDosHeader->e_lfanew - 4 - 
						sizeof(IMAGE_FILE_HEADER) - 
						pFileHeader->SizeOfOptionalHeader - 
						sizeof(IMAGE_SECTION_HEADER) * pFileHeader->NumberOfSections;

	if (RemainingSpace < 2 * sizeof(IMAGE_SECTION_HEADER))
	{
		ret = -5;
		printf("文件头剩余空间不足，无法进行添加节区操作");
		return ret;
	}


	//5、修改相关内容 需要用更高级的指针进行操作
	LPWORD pNumberOfSections	= &pFileHeader->NumberOfSections;
	LPDWORD pSizeOfImage		= &pOptionalHeader->SizeOfImage;

	PVOID pSecName				= &pSectionGroup[pFileHeader->NumberOfSections].Name;
	LPDWORD pSecMisc			= &pSectionGroup[pFileHeader->NumberOfSections].Misc.VirtualSize;
	LPDWORD pSecVirtualAddress	= &pSectionGroup[pFileHeader->NumberOfSections].VirtualAddress;
	LPDWORD pSecSizeOfRawData	= &pSectionGroup[pFileHeader->NumberOfSections].SizeOfRawData;
	LPDWORD pSecPointerToRawData= &pSectionGroup[pFileHeader->NumberOfSections].PointerToRawData;
	LPDWORD pSecCharacteristics	= &pSectionGroup[pFileHeader->NumberOfSections].Characteristics;

	*pNumberOfSections			= pFileHeader->NumberOfSections + 1;
	*pSizeOfImage				= pOptionalHeader->SizeOfImage + 0x1000;

	memcpy(pSecName, ".NewSec", 8);
	*pSecMisc = 0x1000;
	*pSecVirtualAddress = pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize;
	//SectionAlignment对齐
	if (*pSecVirtualAddress % pOptionalHeader->SectionAlignment)
	{
		*pSecVirtualAddress = (*pSecVirtualAddress) / pOptionalHeader->SectionAlignment * pOptionalHeader->SectionAlignment + pOptionalHeader->SectionAlignment;
	}

	*pSecSizeOfRawData = 0x1000;

	*pSecPointerToRawData = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;
	//FileAlignment对齐
	if (*pSecPointerToRawData % pOptionalHeader->FileAlignment)
	{
		*pSecPointerToRawData = (*pSecPointerToRawData) / pOptionalHeader->FileAlignment * pOptionalHeader->FileAlignment + pOptionalHeader->FileAlignment;
	}

	*pSecCharacteristics = 0xFFFFFFFF;


	*pNewLength = NewLength;
	return ret;
}

int main03()
{
	int ret = 0;

	PVOID FileAddress = NULL;
	PVOID NewFileAddress = NULL;
	DWORD NewFileLength = 0;

	//1、将文件读入到内存   
	ret = MyReadFile(&FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//2、在文件中添加一个节区  新开辟一个内存空间
	ret = AddSection(FileAddress, &NewFileAddress, &NewFileLength);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		if (NewFileAddress != NULL)
			free(NewFileAddress);
		return ret;
	}

	//3、将修改后的文件写入硬盘
	ret = MyWriteFile(NewFileAddress, NewFileLength, NEW_FILE);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		if (NewFileAddress != NULL)
			free(NewFileAddress);
		return ret;
	}

	if (FileAddress != NULL)
		free(FileAddress);
	if (NewFileAddress != NULL)
		free(NewFileAddress);

	return ret;
}
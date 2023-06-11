# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"

# define NEW_FILE "C:/Users/Qiu_JY/Desktop/Out.exe"

/*
4.通过编写控制台程序，将一个EXE文件读取到内存，把该文件的最后一个节扩大1000h，并保证程序的正常运行。
*/

int ExtendLastSection(PVOID FileAddress, PVOID *NewFileAddress, PDWORD pNewLength)
{
	int ret = 0;
	DWORD OldLength = 0;
	DWORD NewLength = 0;
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
	pDosHeader = (PIMAGE_DOS_HEADER)(*NewFileAddress);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	pLastSection = &pSectionGroup[pFileHeader->NumberOfSections - 1];

	//4、修改相关内容 需要用更高级的指针进行操作
	LPDWORD pSizeOfImage = &pOptionalHeader->SizeOfImage;
	LPDWORD pSecMisc = &pLastSection->Misc.VirtualSize;
	LPDWORD pSecSizeOfRawData = &pLastSection->SizeOfRawData;

	*pSizeOfImage = *pSizeOfImage + 0x1000;
	*pSecMisc = *pSecMisc + 0x1000;
	*pSecSizeOfRawData = *pSecSizeOfRawData + 0x1000;

	*pNewLength = NewLength;

	return ret;
}


int main04()
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

	
	//2、进行扩展节区操作
	ret = ExtendLastSection(FileAddress, &NewFileAddress, &NewFileLength);
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
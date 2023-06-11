# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"

# define NEW_FILE "C:/Users/Qiu_JY/Desktop/Out.exe"

/*
5.通过编写控制台程序，将一个EXE文件读取到内存，把该文件的所有节进行合并，并保证程序的正常运行。
*/

int MegerAllSection(PVOID FileAddress, PVOID *NewFileAddress, PDWORD pNewLength)
{
	int ret = 0;
	DWORD FileOffset = 0;
	DWORD NewLength = 0;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionGroup = NULL;
	PIMAGE_SECTION_HEADER pLastSection = NULL;

	//0、将指针指向对应位置
	pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	pLastSection = &pSectionGroup[pFileHeader->NumberOfSections - 1];
	//文件偏移 = 第一个节区的RVA - SizeOfHeaders
	FileOffset = pSectionGroup->VirtualAddress - pOptionalHeader->SizeOfHeaders;

	//1、合并节区时需要把所有的节区展开，所以长度会有变化，需要重新计算长度
	//   新长度 = ImageBuffer的大小 - 第一个节区的RVA + SizeOfHeaders
	NewLength = pOptionalHeader->SizeOfImage - FileOffset;

	//2、分配空间
	*NewFileAddress = (PVOID)malloc(NewLength);
	if (*NewFileAddress == NULL)
	{
		ret = -3;
		printf("func malloc() Error!\n");
		return ret;
	}
	memset(*NewFileAddress, 0, NewLength);

	//3、将除第一个节区之外的所有节区在新地址中展开
	//	(1)、拷贝文件头
	memcpy(*NewFileAddress, FileAddress, pOptionalHeader->SizeOfHeaders);
	
	//	(2)、拷贝第一个节
	memcpy((PVOID)((DWORD)*NewFileAddress + pSectionGroup[0].PointerToRawData), 
		   (PVOID)((DWORD)FileAddress + pSectionGroup[0].PointerToRawData), 
		   pSectionGroup[0].SizeOfRawData);

	//	(3)、循环展开拷贝剩余的节
	for (int i = 1; i < pFileHeader->NumberOfSections; i++)
	{
		memcpy((PVOID)((DWORD)*NewFileAddress + pSectionGroup[i].VirtualAddress - FileOffset),
			   (PVOID)((DWORD)FileAddress + pSectionGroup[i].PointerToRawData),
			   pSectionGroup[i].SizeOfRawData);
	}

	//	(4)、修改指针指向
	pDosHeader = (PIMAGE_DOS_HEADER)(*NewFileAddress);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	pLastSection = &pSectionGroup[pFileHeader->NumberOfSections - 1];

	//4、将第一个节的大小、属性更改 
	//	大小 = SizeOfImage - 第一个节的RVA
	//	属性 = 所有节的属性
	PDWORD pSecSizeOfRawData = &pSectionGroup[0].SizeOfRawData;
	PDWORD pSecMisc = &pSectionGroup[0].Misc.VirtualSize;
	PDWORD pCharacteristics = &pSectionGroup[0].Characteristics;

	*pSecSizeOfRawData = pOptionalHeader->SizeOfImage - pSectionGroup[0].VirtualAddress;
	*pSecMisc = pOptionalHeader->SizeOfImage - pSectionGroup[0].VirtualAddress;
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		*pCharacteristics |= pSectionGroup[i].Characteristics;
	}

	//5、抹去第一个节后的所有信息；
	memset(&pSectionGroup[1], 0, sizeof(IMAGE_SECTION_HEADER) * (pFileHeader->NumberOfSections - 1));

	//6、修改节区的数量
	PWORD pNumberOfSections = &pFileHeader->NumberOfSections;
	*pNumberOfSections = 1;

	*pNewLength = NewLength;
	return ret;
}


int main05()
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
	ret = MegerAllSection(FileAddress, &NewFileAddress, &NewFileLength);
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
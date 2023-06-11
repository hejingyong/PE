# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"

/*
2.通过编写控制台程序，将一个EXE文件读取到内存(FileBuffer)，在内存中将它进行拉伸(ImageBuffer)，
  再压缩(NewFileBuffer)，然后将压缩后的NewFileBuffer存盘并可以正常运行，实现PE加载过程。
*/
# define NEW_FILEBUFFER "C:/Users/Qiu_JY/Desktop/Out.exe"



int FileBufferToImageBuffer(PVOID pFileBuffer, PVOID *pImageBuffer)
{
	int ret = 0;
	DWORD ImageBufferSize = 0;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

	//1、获取ImageBufffer的内存大小
	ImageBufferSize = pOptionalHeader->SizeOfImage;

	//2、为pImageBuffer分配内存空间
	*pImageBuffer = (PVOID)malloc(ImageBufferSize);
	if (pImageBuffer == NULL)
	{
		ret = -4;
		printf("func malloc() Error : %d！\n", ret);
		return ret;
	}
	memset(*pImageBuffer, 0, ImageBufferSize);

	//3、将FileBuffer的数据拷贝到ImageBuffer中
	//		文件头直接拷贝
	memcpy(*pImageBuffer, pFileBuffer, pOptionalHeader->SizeOfHeaders);

	//		节区循环拷贝
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		memcpy((PVOID)((DWORD)*pImageBuffer + pSectionGroup[i].VirtualAddress),
			   (PVOID)((DWORD)pFileBuffer + pSectionGroup[i].PointerToRawData), 
			   pSectionGroup[i].SizeOfRawData);
	}

	return ret;
}

int ImageBufferToNewFileBuffer(PVOID pImageBuffer, PVOID* pNewFileBuffer, PDWORD pNewFileBufferSize)
{
	int ret = 0;
	DWORD NewFileBufferSize = 0;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

	//1、获取NewFileBuffer的内存大小
	NewFileBufferSize += pOptionalHeader->SizeOfHeaders;		//文件头大小
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		NewFileBufferSize += pSectionGroup[i].SizeOfRawData;
	}

	//2、为pNewFileBuffer分配内存空间
	*pNewFileBuffer = (PVOID)malloc(NewFileBufferSize);
	if (pNewFileBuffer == NULL)
	{
		ret = -4;
		printf("func malloc() Error : %d！\n", ret);
		return ret;
	}
	memset(*pNewFileBuffer, 0, NewFileBufferSize);

	//3、将ImageBuffer的数据拷贝到NewFileBuffer中
	//		文件头直接拷贝
	memcpy(*pNewFileBuffer, pImageBuffer, pOptionalHeader->SizeOfHeaders);

	//		节区循环拷贝
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		memcpy((PVOID)((DWORD)*pNewFileBuffer + pSectionGroup[i].PointerToRawData),
			   (PVOID)((DWORD)pImageBuffer + pSectionGroup[i].VirtualAddress),
			   pSectionGroup[i].SizeOfRawData);
	}

	*pNewFileBufferSize = NewFileBufferSize;

	return ret;
}



int main02()
{
	int ret = 0;

	PVOID pFileBuffer = NULL;
	PVOID pImageBuffer = NULL;
	PVOID pNewFileBuffer = NULL;
	DWORD NewFileBufferSize = 0;

	//1、将文件读入到内存 FileBuffer
	ret = MyReadFile(&pFileBuffer);
	if (ret != 0)
	{
		if (pFileBuffer != NULL)
			free(pFileBuffer);
		return ret;
	}

	//2、将FileBuffer转换成ImageBuffer
	ret = FileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (ret != 0)
	{
		if (pFileBuffer != NULL)
			free(pFileBuffer);
		if (pImageBuffer != NULL)
			free(pImageBuffer);
		return ret;
	}

	//3、将ImageBuffer转换成NewFileBuffer
	ret = ImageBufferToNewFileBuffer(pImageBuffer, &pNewFileBuffer, &NewFileBufferSize);
	if (ret != 0)
	{
		if (pFileBuffer != NULL)
			free(pFileBuffer);
		if (pImageBuffer != NULL)
			free(pImageBuffer);
		if (pNewFileBuffer != NULL)
			free(pNewFileBuffer);
		return ret;
	}

	//4、将文件写入硬盘
	ret = MyWriteFile(pNewFileBuffer, NewFileBufferSize, NEW_FILEBUFFER);
	if (ret != 0)
	{
		if (pFileBuffer != NULL)
			free(pFileBuffer);
		if (pImageBuffer != NULL)
			free(pImageBuffer);
		if (pNewFileBuffer != NULL)
			free(pNewFileBuffer);
		return ret;
	}

	if (pFileBuffer != NULL)
		free(pFileBuffer);
	if (pImageBuffer != NULL)
		free(pImageBuffer);
	if (pNewFileBuffer != NULL)
		free(pNewFileBuffer);

	return ret;
}
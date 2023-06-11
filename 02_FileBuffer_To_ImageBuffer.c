# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"

/*
2.ͨ����д����̨���򣬽�һ��EXE�ļ���ȡ���ڴ�(FileBuffer)�����ڴ��н�����������(ImageBuffer)��
  ��ѹ��(NewFileBuffer)��Ȼ��ѹ�����NewFileBuffer���̲������������У�ʵ��PE���ع��̡�
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

	//1����ȡImageBufffer���ڴ��С
	ImageBufferSize = pOptionalHeader->SizeOfImage;

	//2��ΪpImageBuffer�����ڴ�ռ�
	*pImageBuffer = (PVOID)malloc(ImageBufferSize);
	if (pImageBuffer == NULL)
	{
		ret = -4;
		printf("func malloc() Error : %d��\n", ret);
		return ret;
	}
	memset(*pImageBuffer, 0, ImageBufferSize);

	//3����FileBuffer�����ݿ�����ImageBuffer��
	//		�ļ�ͷֱ�ӿ���
	memcpy(*pImageBuffer, pFileBuffer, pOptionalHeader->SizeOfHeaders);

	//		����ѭ������
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

	//1����ȡNewFileBuffer���ڴ��С
	NewFileBufferSize += pOptionalHeader->SizeOfHeaders;		//�ļ�ͷ��С
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		NewFileBufferSize += pSectionGroup[i].SizeOfRawData;
	}

	//2��ΪpNewFileBuffer�����ڴ�ռ�
	*pNewFileBuffer = (PVOID)malloc(NewFileBufferSize);
	if (pNewFileBuffer == NULL)
	{
		ret = -4;
		printf("func malloc() Error : %d��\n", ret);
		return ret;
	}
	memset(*pNewFileBuffer, 0, NewFileBufferSize);

	//3����ImageBuffer�����ݿ�����NewFileBuffer��
	//		�ļ�ͷֱ�ӿ���
	memcpy(*pNewFileBuffer, pImageBuffer, pOptionalHeader->SizeOfHeaders);

	//		����ѭ������
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

	//1�����ļ����뵽�ڴ� FileBuffer
	ret = MyReadFile(&pFileBuffer);
	if (ret != 0)
	{
		if (pFileBuffer != NULL)
			free(pFileBuffer);
		return ret;
	}

	//2����FileBufferת����ImageBuffer
	ret = FileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (ret != 0)
	{
		if (pFileBuffer != NULL)
			free(pFileBuffer);
		if (pImageBuffer != NULL)
			free(pImageBuffer);
		return ret;
	}

	//3����ImageBufferת����NewFileBuffer
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

	//4�����ļ�д��Ӳ��
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
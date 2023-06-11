# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"

# define NEW_FILE "C:/Users/Qiu_JY/Desktop/Out.exe"

/*
5.ͨ����д����̨���򣬽�һ��EXE�ļ���ȡ���ڴ棬�Ѹ��ļ������нڽ��кϲ�������֤������������С�
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

	//0����ָ��ָ���Ӧλ��
	pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	pLastSection = &pSectionGroup[pFileHeader->NumberOfSections - 1];
	//�ļ�ƫ�� = ��һ��������RVA - SizeOfHeaders
	FileOffset = pSectionGroup->VirtualAddress - pOptionalHeader->SizeOfHeaders;

	//1���ϲ�����ʱ��Ҫ�����еĽ���չ�������Գ��Ȼ��б仯����Ҫ���¼��㳤��
	//   �³��� = ImageBuffer�Ĵ�С - ��һ��������RVA + SizeOfHeaders
	NewLength = pOptionalHeader->SizeOfImage - FileOffset;

	//2������ռ�
	*NewFileAddress = (PVOID)malloc(NewLength);
	if (*NewFileAddress == NULL)
	{
		ret = -3;
		printf("func malloc() Error!\n");
		return ret;
	}
	memset(*NewFileAddress, 0, NewLength);

	//3��������һ������֮������н������µ�ַ��չ��
	//	(1)�������ļ�ͷ
	memcpy(*NewFileAddress, FileAddress, pOptionalHeader->SizeOfHeaders);
	
	//	(2)��������һ����
	memcpy((PVOID)((DWORD)*NewFileAddress + pSectionGroup[0].PointerToRawData), 
		   (PVOID)((DWORD)FileAddress + pSectionGroup[0].PointerToRawData), 
		   pSectionGroup[0].SizeOfRawData);

	//	(3)��ѭ��չ������ʣ��Ľ�
	for (int i = 1; i < pFileHeader->NumberOfSections; i++)
	{
		memcpy((PVOID)((DWORD)*NewFileAddress + pSectionGroup[i].VirtualAddress - FileOffset),
			   (PVOID)((DWORD)FileAddress + pSectionGroup[i].PointerToRawData),
			   pSectionGroup[i].SizeOfRawData);
	}

	//	(4)���޸�ָ��ָ��
	pDosHeader = (PIMAGE_DOS_HEADER)(*NewFileAddress);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	pLastSection = &pSectionGroup[pFileHeader->NumberOfSections - 1];

	//4������һ���ڵĴ�С�����Ը��� 
	//	��С = SizeOfImage - ��һ���ڵ�RVA
	//	���� = ���нڵ�����
	PDWORD pSecSizeOfRawData = &pSectionGroup[0].SizeOfRawData;
	PDWORD pSecMisc = &pSectionGroup[0].Misc.VirtualSize;
	PDWORD pCharacteristics = &pSectionGroup[0].Characteristics;

	*pSecSizeOfRawData = pOptionalHeader->SizeOfImage - pSectionGroup[0].VirtualAddress;
	*pSecMisc = pOptionalHeader->SizeOfImage - pSectionGroup[0].VirtualAddress;
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		*pCharacteristics |= pSectionGroup[i].Characteristics;
	}

	//5��Ĩȥ��һ���ں��������Ϣ��
	memset(&pSectionGroup[1], 0, sizeof(IMAGE_SECTION_HEADER) * (pFileHeader->NumberOfSections - 1));

	//6���޸Ľ���������
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

	//1�����ļ����뵽�ڴ�   
	ret = MyReadFile(&FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}


	//2��������չ��������
	ret = MegerAllSection(FileAddress, &NewFileAddress, &NewFileLength);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		if (NewFileAddress != NULL)
			free(NewFileAddress);
		return ret;
	}

	//3�����޸ĺ���ļ�д��Ӳ��
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
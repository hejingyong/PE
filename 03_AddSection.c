# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"

# define NEW_FILE "C:/Users/Qiu_JY/Desktop/Out.exe"


/*
3.ͨ����д����̨���򣬽�һ��EXE�ļ���ȡ���ڴ棬�����Ľڱ�������һ���ڱ�ͽ��������̺����������������С�
*/

//��ӽڵ���Ҫ����
int AddSection(PVOID FileAddress, PVOID *NewFileAddress, PDWORD pNewLength)
{
	int ret = 0;

	DWORD OldLength = 0;
	DWORD NewLength = 0;
	DWORD RemainingSpace = 0;	//	ʣ��ռ�
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionGroup = NULL;
	PIMAGE_SECTION_HEADER pLastSection = NULL;

	//1��������չ�ռ�
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

	//���ɵĿռ�����0x1000
	NewLength = OldLength + 0x1000;
	*NewFileAddress = (LPVOID)malloc(NewLength);
	if (*NewFileAddress == NULL)
	{
		ret = -3;
		printf("func malloc() Error!\n");
		return ret;
	}
	memset(*NewFileAddress, 0, NewLength);

	//2�����ɿռ������copy���µĿռ�
	memcpy(*NewFileAddress, FileAddress, OldLength);

	//3����ָ��ָ���Ӧλ��
	pDosHeader		= (PIMAGE_DOS_HEADER)(*NewFileAddress);
	pFileHeader		= (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionGroup	= (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	pLastSection	= &pSectionGroup[pFileHeader->NumberOfSections - 1];

	//4���ж��Ƿ����㹻���ڴ�ռ�
	RemainingSpace =	pOptionalHeader->SizeOfHeaders - 
						pDosHeader->e_lfanew - 4 - 
						sizeof(IMAGE_FILE_HEADER) - 
						pFileHeader->SizeOfOptionalHeader - 
						sizeof(IMAGE_SECTION_HEADER) * pFileHeader->NumberOfSections;

	if (RemainingSpace < 2 * sizeof(IMAGE_SECTION_HEADER))
	{
		ret = -5;
		printf("�ļ�ͷʣ��ռ䲻�㣬�޷�������ӽ�������");
		return ret;
	}


	//5���޸�������� ��Ҫ�ø��߼���ָ����в���
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
	//SectionAlignment����
	if (*pSecVirtualAddress % pOptionalHeader->SectionAlignment)
	{
		*pSecVirtualAddress = (*pSecVirtualAddress) / pOptionalHeader->SectionAlignment * pOptionalHeader->SectionAlignment + pOptionalHeader->SectionAlignment;
	}

	*pSecSizeOfRawData = 0x1000;

	*pSecPointerToRawData = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;
	//FileAlignment����
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

	//1�����ļ����뵽�ڴ�   
	ret = MyReadFile(&FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//2�����ļ������һ������  �¿���һ���ڴ�ռ�
	ret = AddSection(FileAddress, &NewFileAddress, &NewFileLength);
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
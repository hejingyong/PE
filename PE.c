# define _CRT_SECURE_NO_WARNINGS
# include "PE.h"

int GetFileLength(FILE *pf, DWORD *Length)
{
	int ret = 0;

	fseek(pf, 0, SEEK_END);
	*Length = ftell(pf);
	fseek(pf, 0, SEEK_SET);

	return ret;
}

int MyReadFile(void **pFileAddress)
{
	int ret = 0;
	DWORD Length = 0;
	//���ļ�
	FILE* pf = fopen(FILE_PATH, "rb");
	if (pf == NULL)
	{
		ret = -1;
		printf("func ReadFile() Error!\n");
		return ret;
	}

	//��ȡ�ļ�����
	ret = GetFileLength(pf, &Length);
	if (ret != 0 && Length == -1)
	{
		ret = -2;
		printf("func GetFileLength() Error!\n");
		return ret;
	}

	//����ռ�
	*pFileAddress = (PVOID)malloc(Length);
	if (*pFileAddress == NULL)
	{
		ret = -3;
		printf("func malloc() Error!\n");
		return ret;
	}
	memset(*pFileAddress, 0, Length);

	//��ȡ�ļ������ڴ�
	fread(*pFileAddress, Length, 1, pf);

	fclose(pf);
	return ret;
}


int MyReadFile_V2(void** pFileAddress, PCHAR FilePath)
{
	int ret = 0;
	DWORD Length = 0;
	//���ļ�
	FILE* pf = fopen(FilePath, "rb");
	if (pf == NULL)
	{
		ret = -1;
		printf("func ReadFile() Error!\n");
		return ret;
	}

	//��ȡ�ļ�����
	ret = GetFileLength(pf, &Length);
	if (ret != 0 && Length == -1)
	{
		ret = -2;
		printf("func GetFileLength() Error!\n");
		return ret;
	}

	//����ռ�
	*pFileAddress = (PVOID)malloc(Length);
	if (*pFileAddress == NULL)
	{
		ret = -3;
		printf("func malloc() Error!\n");
		return ret;
	}
	memset(*pFileAddress, 0, Length);

	//��ȡ�ļ������ڴ�
	fread(*pFileAddress, Length, 1, pf);

	fclose(pf);
	return ret;
}

int MyWriteFile(PVOID pFileAddress, DWORD FileSize, LPSTR FilePath)
{
	int ret = 0;

	FILE *pf = fopen(FilePath, "wb");
	if (pf == NULL)
	{
		ret = -5;
		printf("func fopen() error :%d!\n", ret);
		return ret;
	}

	fwrite(pFileAddress, FileSize, 1, pf);

	fclose(pf);

	return ret;
}

int FOA_TO_RVA(PVOID FileAddress, DWORD FOA, PDWORD pRVA)
{
	int ret = 0;

	PIMAGE_DOS_HEADER pDosHeader				= (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader				= (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader	= (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup			= (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

	//FOA���ļ�ͷ�� �� SectionAlignment ���� FileAlignment ʱRVA����FOA
	if (FOA < pOptionalHeader->SizeOfHeaders || pOptionalHeader->SectionAlignment == pOptionalHeader->FileAlignment)
	{
		*pRVA = FOA;
		return ret;
	}

	//FOA�ڽ�����
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (FOA >= pSectionGroup[i].PointerToRawData && FOA < pSectionGroup[i].PointerToRawData + pSectionGroup[i].SizeOfRawData)
		{
			*pRVA = pSectionGroup[i].VirtualAddress + FOA - pSectionGroup[i].PointerToRawData;
			return ret;
		}
	}

	//û���ҵ���ַ
	ret = -4;
	printf("func FOA_TO_RAV() Error: %d ��ַת��ʧ�ܣ�\n", ret);
	return ret;
}

int RVA_TO_FOA(PVOID FileAddress, DWORD RVA, PDWORD pFOA)
{
	int ret = 0;

	PIMAGE_DOS_HEADER pDosHeader				= (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader				= (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader	= (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup			= (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

	//RVA���ļ�ͷ�� �� SectionAlignment ���� FileAlignment ʱRVA����FOA
	if (RVA < pOptionalHeader->SizeOfHeaders || pOptionalHeader->SectionAlignment == pOptionalHeader->FileAlignment)
	{
		*pFOA = RVA;
		return ret;
	}

	//RVA�ڽ�����
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (RVA >= pSectionGroup[i].VirtualAddress && RVA < pSectionGroup[i].VirtualAddress + pSectionGroup[i].Misc.VirtualSize)
		{
			*pFOA = pSectionGroup[i].PointerToRawData + RVA - pSectionGroup[i].VirtualAddress;
			return ret;
		}
	}

	//û���ҵ���ַ
	ret = -4;
	printf("func RAV_TO_FOA() Error: %d ��ַת��ʧ�ܣ�\n", ret);
	return ret;
}

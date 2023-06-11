# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"


# define NEW_FILE "C:/Users/Qiu_JY/Desktop/Out.exe"

/*
1����PE�ļ��д���һ���½ڣ�Ȼ�󽫵����INT���ƶ����½��С�����ļ�д��Ӳ�̣���������ȷ���������
   ����IAT��ĵ�ַ�ڳ�����д���������޷��ƶ�IAT��
*/


//��ӽڵ���Ҫ����
int AddSection_V3(PVOID FileAddress, PVOID *NewFileAddress, PDWORD pNewLength)
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

	//Add_ָ���������
	pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//Add_�жϵ�����Ƿ����
	if (pOptionalHeader->DataDirectory[1].VirtualAddress == 0)
	{
		ret = -7;
		printf("RelocationDirectory ������!\n");
		return ret;
	}


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

	//Change_���ɵĿռ����Ӻ��ʵĴ�С���ɵ�����IAT���С ��INT��Ĵ�С���ֳ��Ⱦ����ڵĴ�С(Ϊ�˷���ֱ�Ӷ����0x5000����С)
	NewLength = OldLength + 0x1000 + (pOptionalHeader->DataDirectory[1].Size / 0x1000 * 0x1000 + 0x5000);
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
	pDosHeader = (PIMAGE_DOS_HEADER)(*NewFileAddress);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	pLastSection = &pSectionGroup[pFileHeader->NumberOfSections - 1];

	//4���ж��Ƿ����㹻���ڴ�ռ�
	RemainingSpace = pOptionalHeader->SizeOfHeaders -
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
	LPWORD pNumberOfSections = &pFileHeader->NumberOfSections;
	LPDWORD pSizeOfImage = &pOptionalHeader->SizeOfImage;

	PVOID pSecName = &pSectionGroup[pFileHeader->NumberOfSections].Name;
	LPDWORD pSecMisc = &pSectionGroup[pFileHeader->NumberOfSections].Misc.VirtualSize;
	LPDWORD pSecVirtualAddress = &pSectionGroup[pFileHeader->NumberOfSections].VirtualAddress;
	LPDWORD pSecSizeOfRawData = &pSectionGroup[pFileHeader->NumberOfSections].SizeOfRawData;
	LPDWORD pSecPointerToRawData = &pSectionGroup[pFileHeader->NumberOfSections].PointerToRawData;
	LPDWORD pSecCharacteristics = &pSectionGroup[pFileHeader->NumberOfSections].Characteristics;

	*pNumberOfSections = pFileHeader->NumberOfSections + 1;
	//Change_�޸Ĵ�С
	*pSizeOfImage = pOptionalHeader->SizeOfImage + NewLength - OldLength;

	memcpy(pSecName, ".NewSec", 8);
	//Change_�޸Ĵ�С
	*pSecMisc = NewLength - OldLength;
	*pSecVirtualAddress = pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize;
	//SectionAlignment����
	if (*pSecVirtualAddress % pOptionalHeader->SectionAlignment)
	{
		*pSecVirtualAddress = (*pSecVirtualAddress) / pOptionalHeader->SectionAlignment * pOptionalHeader->SectionAlignment + pOptionalHeader->SectionAlignment;
	}
	//Change_�޸Ĵ�С
	*pSecSizeOfRawData = NewLength - OldLength;

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


int MoveImportTable(PVOID FileAddress)
{
	int ret = 0;

	//1��ָ���������
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pLastSection = &pSectionGroup[pFileHeader->NumberOfSections - 1]; //���һ���ڵ�����

	//2����ȡ�����ĵ�ַ
	DWORD ImportDirectory_RAVAdd = pOptionalHeader->DataDirectory[1].VirtualAddress;
	DWORD ImportDirectory_FOAAdd = 0;
	//	(1)���жϵ�����Ƿ����
	if (ImportDirectory_RAVAdd == 0)
	{
		printf("RelocationDirectory ������!\n");
		return ret;
	}
	//	(2)����ȡ������FOA��ַ
	ret = RVA_TO_FOA(FileAddress, ImportDirectory_RAVAdd, &ImportDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//3��ָ�����
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)FileAddress + ImportDirectory_FOAAdd);

	//4����ȡ���һ���ڵĵ�ַ��Ϊ����Ŀ���ַ
	PVOID NextAddress = (PVOID)((DWORD)FileAddress + pLastSection->PointerToRawData);

	//5��ָ���µĵ�����ַ
	PIMAGE_IMPORT_DESCRIPTOR NewImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)FileAddress + pLastSection->PointerToRawData);

	//6��ѭ����������
	//	1)�Ƚ����еĵ�����ƶ����½�
	DWORD NewImportTableAddress_RVA = 0;
	DWORD NewImportTableAddress_FOA = ((DWORD)NextAddress - (DWORD)FileAddress);
	memcpy(NextAddress, ImportDirectory, pOptionalHeader->DataDirectory[1].Size);	//
	ret = FOA_TO_RVA(FileAddress, NewImportTableAddress_FOA, &NewImportTableAddress_RVA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//	2)��ָ���ƶ�����һ���հ׵�ַ
	NextAddress = (PDWORD)((DWORD)NextAddress + pOptionalHeader->DataDirectory[1].Size);

	
	while (NewImportDirectory->FirstThunk && NewImportDirectory->OriginalFirstThunk)
	{
		//	3)ָ��INT��
		DWORD NewOriginalFirstThunk_RVA = 0;
		DWORD NewOriginalFirstThunk_FOA = (DWORD)NextAddress - (DWORD)FileAddress;
		DWORD OriginalFirstThunk_RVA = NewImportDirectory->OriginalFirstThunk;
		DWORD OriginalFirstThunk_FOA = 0;
		ret = RVA_TO_FOA(FileAddress, OriginalFirstThunk_RVA, &OriginalFirstThunk_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}
		PDWORD OriginalFirstThunk = (PDWORD)((DWORD)FileAddress + OriginalFirstThunk_FOA);
		PDWORD NewOriginalFirstThunk = (PDWORD)NextAddress;
		
		//	4)�����µ�INT���RVA
		ret = FOA_TO_RVA(FileAddress, NewOriginalFirstThunk_FOA, &NewOriginalFirstThunk_RVA);
		if (ret != 0)
		{
			printf("func FOA_TO_RVA() Error!\n");
			return ret;
		}

		//	5)��ȡINT������Ŀ�ĸ���
		DWORD NumberOfThunk = 0;
		while (*OriginalFirstThunk)
		{
			NumberOfThunk++;
			OriginalFirstThunk++;
		}
		NumberOfThunk++;	//�������һ���հ׽ṹ
		OriginalFirstThunk = (PDWORD)((DWORD)FileAddress + OriginalFirstThunk_FOA);

		//	6)��INT���ƶ�����
		memcpy(NextAddress, OriginalFirstThunk, 4 * NumberOfThunk);

		//	7)��ָ���ƶ�����һ���հ׵�ַ
		NextAddress = (PVOID)((DWORD)NextAddress + 4 * NumberOfThunk);
		
		//	8)ѭ��INT��
		while (*NewOriginalFirstThunk)
		{
			//	9)�ж�INT�������  
			if ((*NewOriginalFirstThunk >> 31) == 0)	//���ֵ��� 
			{
				//	10)��ȡ������
				DWORD NewImportNameAdd_RVA = 0;
				DWORD NewImportNameAdd_FOA = (DWORD)NextAddress - (DWORD)FileAddress;
				DWORD ImportNameAdd_RAV = *NewOriginalFirstThunk;
				DWORD ImportNameAdd_FOA = 0;
				ret = RVA_TO_FOA(FileAddress, ImportNameAdd_RAV, &ImportNameAdd_FOA);
				if (ret != 0)
				{
					printf("func RVA_TO_FOA() Error!\n");
					return ret;
				}
				PIMAGE_IMPORT_BY_NAME ImportName = (PIMAGE_IMPORT_BY_NAME)((DWORD)FileAddress + ImportNameAdd_FOA);

				//	11)��ȡ�������ֽṹ��Ĵ�С
				DWORD SizeOfImportByName = 3 + strlen(ImportName->Name);

				//	12)���㵼�����ֽṹ���RVA
				ret = FOA_TO_RVA(FileAddress, NewImportNameAdd_FOA, &NewImportNameAdd_RVA);
				if (ret != 0)
				{
					printf("func FOA_TO_RVA() Error!\n");
					return ret;
				}

				//	13)���������ֽṹ���ƶ�
				memcpy(NextAddress, ImportName, SizeOfImportByName);

				//	14)����INT��
				*NewOriginalFirstThunk = NewImportNameAdd_RVA;

				//	15)��ָ���ƶ�����һ���հ׵�ַ	��һ��IMAGE_IMPORT_BY_NAME
				NextAddress = (PVOID)((DWORD)NextAddress + SizeOfImportByName);
			}

			//	16)ָ����һ��INT
			*NewOriginalFirstThunk++;
		}

		//	17)��ȡ�����ļ���
		DWORD NewNameAdd_RVA = 0;
		DWORD NewNameAdd_FOA = (DWORD)NextAddress - (DWORD)FileAddress;
		DWORD NameAdd_RAV = NewImportDirectory->Name;
		DWORD NameAdd_FOA = 0;
		ret = RVA_TO_FOA(FileAddress, NameAdd_RAV, &NameAdd_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}
		PCHAR ImportName = (PCHAR)((DWORD)FileAddress + NameAdd_FOA);

		//	18)�����µĵ����ļ���RVA
		ret = FOA_TO_RVA(FileAddress, NewNameAdd_FOA, &NewNameAdd_RVA);
		if (ret != 0)
		{
			printf("func FOA_TO_RVA() Error!\n");
			return ret;
		}
		
		//	19)��ȡ�����ļ����ĳ���
		DWORD FileNameLength = strlen(ImportName) + 1;

		//	20)�������ļ����ƶ����½�
		memcpy(NextAddress, ImportName, FileNameLength);

		//	21)ָ����һ�������ַ
		NextAddress = (PVOID)((DWORD)NextAddress + FileNameLength);

		//	22)�����µĵ����
		PDWORD pOriginalFirstThunk = &NewImportDirectory->OriginalFirstThunk;
		PDWORD pName = &NewImportDirectory->Name;

		*pOriginalFirstThunk = NewOriginalFirstThunk_RVA;
		*pName = NewNameAdd_RVA;

		//	23)�������ָ�����
		NewImportDirectory++;
	}

	//7���޸�Ŀ¼��
	PDWORD VirtualAddress = &pOptionalHeader->DataDirectory[1].VirtualAddress;
	*VirtualAddress = NewImportTableAddress_RVA;

	return ret;
}


int main13()
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

	//2�����ļ������һ������  copy֮ǰ�Ĵ��벢�������Ĵ�С����С���޸�
	ret = AddSection_V3(FileAddress, &NewFileAddress, &NewFileLength);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		if (NewFileAddress != NULL)
			free(NewFileAddress);
		return ret;
	}
	
	//3���ƶ������� �����һ������
	ret = MoveImportTable(NewFileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		if (NewFileAddress != NULL)
			free(NewFileAddress);
		return ret;
	}


	//4�����ļ�д���ڴ�
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
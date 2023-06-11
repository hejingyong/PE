# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"

# define NEW_FILE "C:/Users/Qiu_JY/Desktop/Out.exe"

/*
1����PE�ļ��д���һ���½ڣ�Ȼ�󽫵������������Ϣ�ƶ����½��С�����ļ�д��Ӳ�̣���������ȷ����������
*/

//��ӽڵ���Ҫ����
int AddSection_V1(PVOID FileAddress, PVOID *NewFileAddress, PDWORD pNewLength)
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

	//Add_�жϵ������Ƿ����
	if (pOptionalHeader->DataDirectory[0].VirtualAddress == 0)
	{
		ret = -7;
		printf("ExportDirectory ������!\n");
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

	//Change_���ɵĿռ����Ӻ��ʵĴ�С���ɵ������С�������4k���롣
	NewLength = OldLength + 0x1000 + (pOptionalHeader->DataDirectory[0].Size / 0x1000 * 0x1000);
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


int MoveExportTable(PVOID FileAddress)
{
	int ret = 0;
	//1��ָ���������
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pLastSection = &pSectionGroup[pFileHeader->NumberOfSections - 1]; //���һ���ڵ�����

	//	ָ�����һ����
	PVOID pLastSectionAddress = (PVOID)((DWORD)FileAddress + pLastSection->PointerToRawData);


	//2����ȡ������ĵ�ַ
	DWORD ExportDirectory_RAVAdd = pOptionalHeader->DataDirectory[0].VirtualAddress;
	DWORD ExportDirectory_FOAAdd = 0;
	//	(1)���жϵ������Ƿ����
	if (ExportDirectory_RAVAdd == 0)
	{
		printf("ExportDirectory ������!\n");
		return ret;
	}
	//	(2)����ȡ�������FOA��ַ
	ret = RVA_TO_FOA(FileAddress, ExportDirectory_RAVAdd, &ExportDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//3��ָ�򵼳���
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)FileAddress + ExportDirectory_FOAAdd);

	//4�������ƶ�������ַ��
	//	1)�ҵ�������ַ��
	DWORD NewAddressOfFunction_RVA = 0;
	DWORD NewAddressOfFunction_FOA = 0;
	DWORD AddressOfFunctions_RVA = ExportDirectory->AddressOfFunctions;
	DWORD AddressOfFunctions_FOA = 0;
	ret = RVA_TO_FOA(FileAddress, AddressOfFunctions_RVA, &AddressOfFunctions_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//	2)��������ַ�������½���
	memcpy(pLastSectionAddress, (PVOID)((DWORD)FileAddress + AddressOfFunctions_FOA), 4 * ExportDirectory->NumberOfFunctions);
	
	//	3)�����µ�RVA
	NewAddressOfFunction_FOA = pLastSection->PointerToRawData;
	ret = FOA_TO_RVA(FileAddress, NewAddressOfFunction_FOA, &NewAddressOfFunction_RVA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//	4)��ȡ��һ�������ַ
	PVOID NextAddress = (PVOID)((DWORD)pLastSectionAddress + 4 * ExportDirectory->NumberOfFunctions);

	//5���ƶ�������ű�
	//	1)�ҵ�������ű�
	DWORD NewAddressOfOrdinal_RVA = 0;
	DWORD NewAddressOfOrdinal_FOA = 0;
	DWORD AddressOfOrdinal_RVA = ExportDirectory->AddressOfNameOrdinals;
	DWORD AddressOfOrdinal_FOA = 0;
	ret = RVA_TO_FOA(FileAddress, AddressOfOrdinal_RVA, &AddressOfOrdinal_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//	2)��������ű������½���
	memcpy(NextAddress, (PVOID)((DWORD)FileAddress + AddressOfOrdinal_FOA), 2 * ExportDirectory->NumberOfNames);
	
	//	3)�����µ�RVA
	NewAddressOfOrdinal_FOA = NewAddressOfFunction_FOA + 4 * ExportDirectory->NumberOfFunctions;
	ret = FOA_TO_RVA(FileAddress, NewAddressOfOrdinal_FOA, &NewAddressOfOrdinal_RVA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//	4)��ȡ��һ�������ַ
	NextAddress = (PVOID)((DWORD)NextAddress + 2 * ExportDirectory->NumberOfNames);

	//6���ƶ��������Ʊ�
	//	1)�ҵ��������Ʊ�
	DWORD NewAddressOfName_RVA = 0;
	DWORD NewAddressOfName_FOA = 0;
	DWORD AddressOfName_RVA = ExportDirectory->AddressOfNames;
	DWORD AddressOfName_FOA = 0;
	ret = RVA_TO_FOA(FileAddress, AddressOfName_RVA, &AddressOfName_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//	2)��������ű������½���
	memcpy(NextAddress, (PVOID)((DWORD)FileAddress + AddressOfName_FOA), 4 * ExportDirectory->NumberOfNames);

	//	3)�����µ�RVA
	NewAddressOfName_FOA = NewAddressOfOrdinal_FOA + 2 * ExportDirectory->NumberOfNames;
	ret = FOA_TO_RVA(FileAddress, NewAddressOfName_FOA, &NewAddressOfName_RVA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//	4)��ȡ��һ�������ַ
	NextAddress = (PVOID)((DWORD)NextAddress + 4 * ExportDirectory->NumberOfNames);

	//7��ѭ��������������˳���޸���������
	//	1)ָ���µĺ�������
	PDWORD pFunctionNameTable = (PDWORD)((DWORD)FileAddress + NewAddressOfName_FOA);

	for (DWORD i = 0; i < ExportDirectory->NumberOfNames; i++)
	{
		DWORD NewFuncName_RVA = 0;
		DWORD NewFuncName_FOA = 0;
		DWORD FuncName_RVA = pFunctionNameTable[i];
		DWORD FuncName_FOA = 0;
		ret = RVA_TO_FOA(FileAddress, FuncName_RVA, &FuncName_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}

		//	2)�ҵ�������
		PCHAR FuncName = (PCHAR)((DWORD)FileAddress + FuncName_FOA);
		
		//	3)���㺯��������
		DWORD FuncNameLength = strlen(FuncName) + 1;

		//	4)����������
		memcpy(NextAddress, FuncName, FuncNameLength);

		//	5)�����µĺ�������ַRVA
		NewFuncName_FOA = (DWORD)NextAddress - (DWORD)FileAddress;
		ret = FOA_TO_RVA(FileAddress, NewFuncName_FOA, &NewFuncName_RVA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}

		//	6)������������
		pFunctionNameTable[i] = NewFuncName_RVA;

		//	7)������һ�������ַ
		NextAddress = (PVOID)((DWORD)NextAddress + FuncNameLength);
	}

	//8�������ļ���
	//	1)�ҵ��ļ���
	DWORD NewFileName_RVA = 0;
	DWORD NewFileName_FOA = 0;
	DWORD FileName_RVA = ExportDirectory->Name;
	DWORD FileName_FOA = 0;
	ret = RVA_TO_FOA(FileAddress, FileName_RVA, &FileName_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	PCHAR FileName = (PCHAR)((DWORD)FileAddress + FileName_FOA);

	//	2)�����ļ�������
	DWORD FileNameLength = strlen(FileName) + 1;

	//	3)�����ļ���
	memcpy(NextAddress, FileName, FileNameLength);

	//	4)�����µ��ļ�����ַRVA
	NewFileName_FOA = (DWORD)NextAddress - (DWORD)FileAddress;
	ret = FOA_TO_RVA(FileAddress, NewFileName_FOA, &NewFileName_RVA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//	5)������һ�������ַ
	NextAddress = (PVOID)((DWORD)NextAddress + FileNameLength);

	//9������������ṹ��
	DWORD NewExportDirectory_RAVAdd = 0;
	DWORD NewExportDirectory_FOAAdd = 0;

	//	1)����������
	memcpy(NextAddress, ExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY));

	//	2)�����µĵ������ַRVA
	NewExportDirectory_FOAAdd = (DWORD)NextAddress - (DWORD)FileAddress;
	ret = FOA_TO_RVA(FileAddress, NewExportDirectory_FOAAdd, &NewExportDirectory_RAVAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//10���޸��������е�ֵ
	//	1)ָ���µĵ�����
	PIMAGE_EXPORT_DIRECTORY pNewExportDirectory = NextAddress;
	
	//	2)ָ����Ҫ�޸ĵ�����
	PDWORD pExportName = &pNewExportDirectory->Name;
	PDWORD pExportAddressOfFunctions = &pNewExportDirectory->AddressOfFunctions;
	PDWORD pExportAddressOfNameOrdinals = &pNewExportDirectory->AddressOfNameOrdinals;
	PDWORD pExportAddressOfNames = &pNewExportDirectory->AddressOfNames;

	//	3)�޸�����
	*pExportName = NewFileName_RVA;
	*pExportAddressOfFunctions = NewAddressOfFunction_RVA;
	*pExportAddressOfNameOrdinals = NewAddressOfOrdinal_RVA;
	*pExportAddressOfNames = NewAddressOfName_RVA;

	//11���޸�Ŀ¼��ĵ�ַ
	PDWORD pVirtualAddress = &pOptionalHeader->DataDirectory[0].VirtualAddress;
	*pVirtualAddress = NewExportDirectory_RAVAdd;

	return ret;
}


int main08()
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
	ret = AddSection_V1(FileAddress, &NewFileAddress, &NewFileLength);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		if (NewFileAddress != NULL)
			free(NewFileAddress);
		return ret;
	}

	//3���ƶ������� �����һ������
	ret = MoveExportTable(NewFileAddress);
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
# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"


/*
1����ӡ��������Ϣ������ӡ��������ַ������������ű�

2��ͬʱд�������ֲ��Һ�����ַ������Ų��Һ�����ַ��غ�����
*/


int PrintFunctionAddressTable(PVOID FileAddress, DWORD AddressOfFunctions_RVA, DWORD NumberOfFunctions)
{
	int ret = 0;
	DWORD AddressOfFunctions_FOA = 0;

	//1��RVA --> FOA
	ret = RVA_TO_FOA(FileAddress, AddressOfFunctions_RVA, &AddressOfFunctions_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//2��ָ������ַ��
	PDWORD FuncAddressTable = (PDWORD)((DWORD)FileAddress + AddressOfFunctions_FOA);

	//2��ѭ����ӡ������ַ��
	printf("=================== ������ַ�� Start ===================\n");
	for (DWORD i = 0; i < NumberOfFunctions; i++)
	{
		DWORD FuncAddress_RVA = FuncAddressTable[i];
		DWORD FuncAddress_FOA = 0;
		ret = RVA_TO_FOA(FileAddress, FuncAddress_RVA, &FuncAddress_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}

		printf("������ַRVA    : %08X  |������ַFOA    : %08X  \n", FuncAddress_RVA, FuncAddress_FOA);
	}
	printf("=================== ������ַ�� End   ===================\n\n");
	return ret;
}


//��ӡ������ű�
int PrintFunctionOrdinalTable(PVOID FileAddress, DWORD AddressOfOrdinal_RVA, DWORD NumberOfNames, DWORD Base)
{
	int ret = 0;
	DWORD AddressOfOrdinal_FOA = 0;

	//1��RVA --> FOA
	ret = RVA_TO_FOA(FileAddress, AddressOfOrdinal_RVA, &AddressOfOrdinal_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//2��ָ������ű�
	PWORD OrdinalTable = (PWORD)((DWORD)FileAddress + AddressOfOrdinal_FOA);

	//3��ѭ����ӡ������ű�
	printf("=================== ������ű� Start ===================\n");
	for (DWORD i = 0; i < NumberOfNames; i++)
	{
		printf("�������  :%04X  |Base+Ordinal   :%04X\n", OrdinalTable[i], OrdinalTable[i] + Base);
	}
	printf("=================== ������ű� End   ===================\n\n");
	return ret;
}


int PrintFunctionNameTable(PVOID FileAddress, DWORD AddressOfNames_RVA, DWORD NumberOfNames)
{
	int ret = 0;
	DWORD AddressOfNames_FOA = 0;
	
	//1��RVA --> FOA
	ret = RVA_TO_FOA(FileAddress, AddressOfNames_RVA, &AddressOfNames_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//2��ָ��������
	PDWORD NameTable = (PDWORD)((DWORD)FileAddress + AddressOfNames_FOA);

	//3��ѭ����ӡ������ű�
	printf("=================== �������� Start ===================\n");
	for (DWORD i = 0; i < NumberOfNames; i++)
	{
		DWORD FuncName_RVA = NameTable[i];
		DWORD FuncName_FOA = 0;
		ret = RVA_TO_FOA(FileAddress, FuncName_RVA, &FuncName_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}
		PCHAR FuncName = (PCHAR)((DWORD)FileAddress + FuncName_FOA);

		printf("������  :%s\n", FuncName);
	}
	printf("=================== �������� End   ===================\n\n");
	
	return ret;
}

int PrintExportTable(PVOID FileAddress)
{
	int ret = 0;

	//1��ָ���������
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

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

	//4���ҵ��ļ���
	DWORD FileName_RVA = ExportDirectory->Name;
	DWORD FileName_FOA = 0;
	ret = RVA_TO_FOA(FileAddress, FileName_RVA, &FileName_FOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}
	PCHAR FileName = (PCHAR)((DWORD)FileAddress + FileName_FOA);

	//5����ӡ��������Ϣ
	printf("DWORD Characteristics;        :  %08X\n", ExportDirectory->Characteristics);
	printf("DWORD TimeDateStamp;          :  %08X\n", ExportDirectory->TimeDateStamp);
	printf("WORD  MajorVersion;           :  %04X\n", ExportDirectory->MajorVersion);
	printf("WORD  MinorVersion;           :  %04X\n", ExportDirectory->MinorVersion);
	printf("DWORD Name;                   :  %08X     \"%s\"\n", ExportDirectory->Name, FileName);
	printf("DWORD Base;                   :  %08X\n", ExportDirectory->Base);
	printf("DWORD NumberOfFunctions;      :  %08X\n", ExportDirectory->NumberOfFunctions);
	printf("DWORD NumberOfNames;          :  %08X\n", ExportDirectory->NumberOfNames);
	printf("DWORD AddressOfFunctions;     :  %08X\n", ExportDirectory->AddressOfFunctions);
	printf("DWORD AddressOfNames;         :  %08X\n", ExportDirectory->AddressOfNames);
	printf("DWORD AddressOfNameOrdinals;  :  %08X\n", ExportDirectory->AddressOfNameOrdinals);
	printf("=========================================================\n");
	printf("*********************************************************\n");

	//6����ӡ������ַ�� ������NumberOfFunctions����
	ret = PrintFunctionAddressTable(FileAddress, ExportDirectory->AddressOfFunctions, ExportDirectory->NumberOfFunctions);
	if (ret != 0)
	{
		printf("func PrintFunctionAddressTable() Error!\n");
		return ret;
	}

	//7����ӡ������ű� ������NumberOfNames����
	ret = PrintFunctionOrdinalTable(FileAddress, ExportDirectory->AddressOfNameOrdinals, ExportDirectory->NumberOfNames, ExportDirectory->Base);
	if (ret != 0)
	{
		printf("func PrintFunctionOrdinalTable() Error!\n");
		return ret;
	}

	//8����ӡ�������� ������NumberOfNames����
	ret = PrintFunctionNameTable(FileAddress, ExportDirectory->AddressOfNames, ExportDirectory->NumberOfNames);
	if (ret != 0)
	{
		printf("func PrintFunctionNameTable() Error!\n");
		return ret;
	}

	return ret;
}

//===============================================================================================

int GetProcAddressByName(PVOID FileAddress, PCHAR pFuncName, PDWORD FuncAddressRVA)
{
	int ret = 0;

	//1��ָ���������
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

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

	//4��ָ��������
	DWORD FuncNameTableRVA = ExportDirectory->AddressOfNames;
	DWORD FuncNameTableFOA = 0;
	ret = RVA_TO_FOA(FileAddress, FuncNameTableRVA, &FuncNameTableFOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}
	PDWORD FuncNameTable = (PDWORD)((DWORD)FileAddress + FuncNameTableFOA);

	//5��������������
	for (DWORD i = 0; i < ExportDirectory->NumberOfNames; i++)
	{
		DWORD FuncNameRVA = FuncNameTable[i];
		DWORD FuncNameFOA = 0;
		ret = RVA_TO_FOA(FileAddress, FuncNameRVA, &FuncNameFOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}
		PCHAR FuncName = (PCHAR)((DWORD)FileAddress + FuncNameFOA);

		//6���ҵ���ͬ�ĺ�����
		if (memcmp(FuncName, pFuncName, strlen(pFuncName)) == 0)
		{
			//7�����������ĺ�����ŵ�����ֵ
			DWORD dwFuncOrdinalIndex = i;

			//8���ҵ�������ű�
			DWORD FuncOrdinalTableRVA = ExportDirectory->AddressOfNameOrdinals;
			DWORD FuncOrdinalTableFOA = 0;
			ret = RVA_TO_FOA(FileAddress, FuncOrdinalTableRVA, &FuncOrdinalTableFOA);
			if (ret != 0)
			{
				printf("func RVA_TO_FOA() Error!\n");
				return ret;
			}
			PWORD FuncOrdinalTable = (PWORD)((DWORD)FileAddress + FuncOrdinalTableFOA);

			//9����ȡ�������
			WORD wFuncOrdinal = FuncOrdinalTable[dwFuncOrdinalIndex];

			//10���ҵ�������ַ��
			DWORD FuncAddressTableRVA = ExportDirectory->AddressOfFunctions;
			DWORD FuncAddressTableFOA = 0;
			ret = RVA_TO_FOA(FileAddress, FuncAddressTableRVA, &FuncAddressTableFOA);
			if (ret != 0)
			{
				printf("func RVA_TO_FOA() Error!\n");
				return ret;
			}
			PDWORD FuncAddressTable = (PDWORD)((DWORD)FileAddress + FuncAddressTableFOA);

			//11����ȡ������ַ
			*FuncAddressRVA = FuncAddressTable[wFuncOrdinal];

			break;
		}
	}
	
	return ret;
}


int GetProcAddressByOrdinal(PVOID FileAddress, WORD wFuncOrdinal, PDWORD FuncAddressRVA)
{
	int ret = 0;
	
	//1��ָ���������
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

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
	
	//4����ȡ�������
	DWORD FuncOrdinal = wFuncOrdinal - ExportDirectory->Base;
	
	//5���ҵ�������ַ��
	DWORD FuncAddressTableRVA = ExportDirectory->AddressOfFunctions;
	DWORD FuncAddressTableFOA = 0;
	ret = RVA_TO_FOA(FileAddress, FuncAddressTableRVA, &FuncAddressTableFOA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}
	PDWORD FuncAddressTable = (PDWORD)((DWORD)FileAddress + FuncAddressTableFOA);

	//11����ȡ������ַ
	*FuncAddressRVA = FuncAddressTable[FuncOrdinal];

	return ret;
}

int main07()
{
	int ret = 0;
	PVOID FileAddress = NULL;


	//1�����ļ����뵽�ڴ�   
	ret = MyReadFile(&FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//2����ӡ������
	ret = PrintExportTable(FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//3�������ֲ��Һ�����ַ
	DWORD FuncAddressRVA = 0;
	PCHAR FuncName = "_Assemble";
	ret = GetProcAddressByName(FileAddress, FuncName, &FuncAddressRVA);
	if (ret != 0)
	{
		printf("func GetProcAddressByName Error!\n");
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}
	printf("������ַRVA:  %08X  |�������� %s  \n\n", FuncAddressRVA, FuncName);


	//4������Ų��Һ�����ַ
	FuncAddressRVA = 0;
	WORD FuncOrdinal = 4;
	ret = GetProcAddressByOrdinal(FileAddress, FuncOrdinal, &FuncAddressRVA);
	if (ret != 0)
	{
		printf("func GetProcAddressByOrdinal Error!\n");
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}
	printf("������ַRVA:  %08X  |������ţ� %04X  \n", FuncAddressRVA, FuncOrdinal);


	if (FileAddress != NULL)
		free(FileAddress);

	system("pause");
	return ret;
}
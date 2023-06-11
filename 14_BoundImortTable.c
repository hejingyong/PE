# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"


/*
1����λ�󶨵��������ӡ���󶨵�����е�����
*/


int PrintBoundImportTable(PVOID FileAddress)
{
	int ret = 0;
	//1��ָ���������
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2����ȡ�󶨵����ĵ�ַ
	DWORD BoundImportDirectory_RVAAdd = pOptionalHeader->DataDirectory[11].VirtualAddress;
	DWORD BoundImportDirectory_FOAAdd = 0;
	//	(1)���жϰ󶨵�����Ƿ����
	if (BoundImportDirectory_RVAAdd == 0)
	{
		printf("BoundImportDirectory ������!\n");
		return ret;
	}
	//	(2)����ȡ�󶨵�����FOA��ַ
	ret = RVA_TO_FOA(FileAddress, BoundImportDirectory_RVAAdd, &BoundImportDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//3��ָ��󶨵����
	PIMAGE_BOUND_IMPORT_DESCRIPTOR BoundImportDirectory = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)FileAddress + BoundImportDirectory_FOAAdd);
	

	//4����ȡ�󶨵����Ļ�ַ
	DWORD BaseBoundImport = (DWORD)BoundImportDirectory;

	//5��ѭ����ӡ�󶨵������Ϣ
	while (BoundImportDirectory->OffsetModuleName && BoundImportDirectory->TimeDateStamp)
	{
		//	1)ָ��ģ����
		PCHAR pModuleName = (PCHAR)(BaseBoundImport + BoundImportDirectory->OffsetModuleName);

		//	2)��ӡ�󶨵������Ϣ
		printf("ModuleName                  :%s\n", pModuleName);
		printf("TimeDateStamp               :%08X\n", BoundImportDirectory->TimeDateStamp);
		printf("NumberOfModuleForwarderRefs :%04X\n", BoundImportDirectory->NumberOfModuleForwarderRefs);
		printf("================ Start =========================\n");
		//	3)ѭ�������ṹ
		for (DWORD i = 0; i < BoundImportDirectory->NumberOfModuleForwarderRefs; i++)
		{
			//	4)ָ������ṹ
			PIMAGE_BOUND_FORWARDER_REF BoundImport_Ref = (PIMAGE_BOUND_FORWARDER_REF)&BoundImportDirectory[i + 1];//�����ṹ��Сһ��

			//	5)ָ��ģ����
			pModuleName = (PCHAR)(BaseBoundImport + BoundImport_Ref->OffsetModuleName);

			//	6)��ӡ��Ϣ
			printf("ModuleName-----------:%s\n", pModuleName);
			printf("TimeDateStamp--------:%08X\n\n", BoundImport_Ref->TimeDateStamp);
			
		}
		printf("================  End  =========================\n");

		//	7)ָ����һ���ṹ
		BoundImportDirectory = &BoundImportDirectory[BoundImportDirectory->NumberOfModuleForwarderRefs + 1];
	}

	return ret;
}

int main14()
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

	//2����ӡ�󶨵�������Ϣ
	ret = PrintBoundImportTable(FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	if (FileAddress != NULL)
		free(FileAddress);

	system("pause");
	return ret;
}
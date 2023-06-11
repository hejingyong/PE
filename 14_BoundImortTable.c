# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"


/*
1、定位绑定导入表，并打印出绑定导入表中的内容
*/


int PrintBoundImportTable(PVOID FileAddress)
{
	int ret = 0;
	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2、获取绑定导入表的地址
	DWORD BoundImportDirectory_RVAAdd = pOptionalHeader->DataDirectory[11].VirtualAddress;
	DWORD BoundImportDirectory_FOAAdd = 0;
	//	(1)、判断绑定导入表是否存在
	if (BoundImportDirectory_RVAAdd == 0)
	{
		printf("BoundImportDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取绑定导入表的FOA地址
	ret = RVA_TO_FOA(FileAddress, BoundImportDirectory_RVAAdd, &BoundImportDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//3、指向绑定导入表
	PIMAGE_BOUND_IMPORT_DESCRIPTOR BoundImportDirectory = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)FileAddress + BoundImportDirectory_FOAAdd);
	

	//4、获取绑定导入表的基址
	DWORD BaseBoundImport = (DWORD)BoundImportDirectory;

	//5、循环打印绑定导入表信息
	while (BoundImportDirectory->OffsetModuleName && BoundImportDirectory->TimeDateStamp)
	{
		//	1)指向模块名
		PCHAR pModuleName = (PCHAR)(BaseBoundImport + BoundImportDirectory->OffsetModuleName);

		//	2)打印绑定导入表信息
		printf("ModuleName                  :%s\n", pModuleName);
		printf("TimeDateStamp               :%08X\n", BoundImportDirectory->TimeDateStamp);
		printf("NumberOfModuleForwarderRefs :%04X\n", BoundImportDirectory->NumberOfModuleForwarderRefs);
		printf("================ Start =========================\n");
		//	3)循环后续结构
		for (DWORD i = 0; i < BoundImportDirectory->NumberOfModuleForwarderRefs; i++)
		{
			//	4)指向后续结构
			PIMAGE_BOUND_FORWARDER_REF BoundImport_Ref = (PIMAGE_BOUND_FORWARDER_REF)&BoundImportDirectory[i + 1];//两个结构大小一样

			//	5)指向模块名
			pModuleName = (PCHAR)(BaseBoundImport + BoundImport_Ref->OffsetModuleName);

			//	6)打印信息
			printf("ModuleName-----------:%s\n", pModuleName);
			printf("TimeDateStamp--------:%08X\n\n", BoundImport_Ref->TimeDateStamp);
			
		}
		printf("================  End  =========================\n");

		//	7)指向下一个结构
		BoundImportDirectory = &BoundImportDirectory[BoundImportDirectory->NumberOfModuleForwarderRefs + 1];
	}

	return ret;
}

int main14()
{
	
	int ret = 0;

	PVOID FileAddress = NULL;

	//1、将文件读入到内存   
	ret = MyReadFile(&FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//2、打印绑定导入表的信息
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
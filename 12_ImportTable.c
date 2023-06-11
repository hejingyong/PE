# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"


/*
1、定位导入表，并打印出导入表中的内容、同时打印出INT表和IAT表
*/

int PrintImportTable(PVOID FileAddress)
{
	int ret = 0;
	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2、获取导入表的地址
	DWORD ImportDirectory_RVAAdd = pOptionalHeader->DataDirectory[1].VirtualAddress;
	DWORD ImportDirectory_FOAAdd = 0;
	//	(1)、判断导入表是否存在
	if (ImportDirectory_RVAAdd == 0)
	{
		printf("ImportDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取导入表的FOA地址
	ret = RVA_TO_FOA(FileAddress, ImportDirectory_RVAAdd, &ImportDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//3、指向导入表
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)FileAddress + ImportDirectory_FOAAdd);

	//4、循环打印每一个导入表的信息  重要成员为0时结束循环
	while (ImportDirectory->FirstThunk && ImportDirectory->OriginalFirstThunk)
	{
		//	(1)获取导入文件的名字
		DWORD ImportNameAdd_RVA = ImportDirectory->Name;
		DWORD ImportNameAdd_FOA = 0;
		ret = RVA_TO_FOA(FileAddress, ImportNameAdd_RVA, &ImportNameAdd_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}
		PCHAR pImportName = (PCHAR)((DWORD)FileAddress + ImportNameAdd_FOA);
		
		printf("=========================ImportTable %s Start=============================\n", pImportName);
		printf("OriginalFirstThunk RVA:%08X\n", ImportDirectory->OriginalFirstThunk);
		
		//	(2)指向INT表
		DWORD OriginalFirstThunk_RVA = ImportDirectory->OriginalFirstThunk;
		DWORD OriginalFirstThunk_FOA = 0;
		ret = RVA_TO_FOA(FileAddress, OriginalFirstThunk_RVA, &OriginalFirstThunk_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}
		PDWORD OriginalFirstThunk_INT = (PDWORD)((DWORD)FileAddress + OriginalFirstThunk_FOA);
		
		//	(3)循环打印INT表的内容		当内容为0时结束
		while (*OriginalFirstThunk_INT)
		{
			//	(4)进行判断,如果最高位为1则是按序号导入信息,去掉最高位就是函数序号,否则是名字导入
			if ((*OriginalFirstThunk_INT) >> 31)	//最高位是1,序号导入
			{
				//	(5)获取函数序号
				DWORD Original = *OriginalFirstThunk_INT << 1 >> 1;	//去除最高标志位。
				printf("按序号导入: %08Xh -- %08dd\n", Original, Original);	//16进制 -- 10 进制
			}
			else	//名字导入
			{
				//	(5)获取函数名
				DWORD ImportNameAdd_RAV = *OriginalFirstThunk_INT;
				DWORD ImportNameAdd_FOA = 0;
				ret = RVA_TO_FOA(FileAddress, ImportNameAdd_RAV, &ImportNameAdd_FOA);
				if (ret != 0)
				{
					printf("func RVA_TO_FOA() Error!\n");
					return ret;
				}
				PIMAGE_IMPORT_BY_NAME ImportName = (PIMAGE_IMPORT_BY_NAME)((DWORD)FileAddress + ImportNameAdd_FOA);
				printf("按名字导入[HINT/NAME]: %02X--%s\n", ImportName->Hint, ImportName->Name);
			}

			//	(6)指向下一个地址
			OriginalFirstThunk_INT++;
		}
		printf("----------------------------------------------------------------\n");
		printf("FirstThunk RVA   :%08X\n", ImportDirectory->FirstThunk);
		printf("TimeDateStamp    :%08X\n", ImportDirectory->TimeDateStamp);

		//	(2)指向IAT表
		DWORD FirstThunk_RVA = ImportDirectory->FirstThunk;
		DWORD FirstThunk_FOA = 0;
		ret = RVA_TO_FOA(FileAddress, FirstThunk_RVA, &FirstThunk_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}
		PDWORD FirstThunk_IAT = (PDWORD)((DWORD)FileAddress + FirstThunk_FOA);

		//	(3)判断IAT表是否被绑定	时间戳 = 0:没有绑定地址	时间戳 = 0xFFFFFFFF:绑定地址	——知识在绑定导入表中
		if (ImportDirectory->TimeDateStamp == 0xFFFFFFFF)
		{
			while (*FirstThunk_IAT)
			{
				printf("绑定函数地址: %08X\n", *FirstThunk_IAT);
				FirstThunk_IAT++;
			}
		}
		else
		{
			//	(4)循环打印IAT表的内容		当内容为0时结束	打印方法和INT表一样
			while (*FirstThunk_IAT)
			{
				//	(5)进行判断,如果最高位为1则是按序号导入信息,去掉最高位就是函数序号,否则是名字导入
				if ((*FirstThunk_IAT) >> 31)	//最高位是1,序号导入
				{
					//	(6)获取函数序号
					DWORD Original = *FirstThunk_IAT << 1 >> 1;	//去除最高标志位。
					printf("按序号导入: %08Xh -- %08dd\n", Original, Original);	//16进制 -- 10 进制
				}
				else	//名字导入
				{
					//	(7)获取函数名
					DWORD ImportNameAdd_RAV = *FirstThunk_IAT;
					DWORD ImportNameAdd_FOA = 0;
					ret = RVA_TO_FOA(FileAddress, ImportNameAdd_RAV, &ImportNameAdd_FOA);
					if (ret != 0)
					{
						printf("func RVA_TO_FOA() Error!\n");
						return ret;
					}
					PIMAGE_IMPORT_BY_NAME ImportName = (PIMAGE_IMPORT_BY_NAME)((DWORD)FileAddress + ImportNameAdd_FOA);
					printf("按名字导入[HINT/NAME]: %02X--%s\n", ImportName->Hint, ImportName->Name);
				}

				FirstThunk_IAT++;
			}

		}
		
		printf("=========================ImportTable %s End  =============================\n", pImportName);

		//	(8)指向下一个导入表
		ImportDirectory++;
	}

	return ret;
}

int main12()
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

	//2、打印导入表信息
	ret = PrintImportTable(FileAddress);
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
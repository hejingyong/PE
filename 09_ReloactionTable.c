# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"


/*
1、定位重定位表，并打印出重定位表内数据以及需要重定位的内容
*/


int PrintReloactionTable(PVOID FileAddress)
{
	int ret = 0;

	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2、获取重定位表的地址
	DWORD RelocationDirectory_RAVAdd = pOptionalHeader->DataDirectory[5].VirtualAddress;
	DWORD RelocationDirectory_FOAAdd = 0;
	//	(1)、判断重定位表是否存在
	if (RelocationDirectory_RAVAdd == 0)
	{
		printf("RelocationDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取重定位表的FOA地址
	ret = RVA_TO_FOA(FileAddress, RelocationDirectory_RAVAdd, &RelocationDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//3、指向重定位表
	PIMAGE_BASE_RELOCATION RelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)FileAddress + RelocationDirectory_FOAAdd);

	//4、循环打印重定位信息  当VirtualAddress和SizeOfBlock都为0时遍历完成
	while (RelocationDirectory->VirtualAddress && RelocationDirectory->SizeOfBlock)
	{
		printf("VirtualAddress    :%08X\n", RelocationDirectory->VirtualAddress);
		printf("SizeOfBlock       :%08X\n", RelocationDirectory->SizeOfBlock);
		printf("================= BlockData Start ======================\n");
		//5、计算在当前块中的数据个数
		DWORD DataNumber = (RelocationDirectory->SizeOfBlock - 8) / 2;

		//6、指向数据块
		PWORD DataGroup = (PWORD)((DWORD)RelocationDirectory + 8);

		//7、循环打印数据块中的数据
		for (DWORD i = 0; i < DataNumber; i++)
		{
			//(1)判断高4位是否为0
			if (DataGroup[i] >> 12 != 0)
			{
				//(2)提取数据块中的有效数据 低12位
				WORD BlockData = DataGroup[i] & 0xFFF;

				//(3)计算数据块的RVA和FOA
				DWORD Data_RVA = RelocationDirectory->VirtualAddress + BlockData;
				DWORD Data_FOA = 0;
				ret = RVA_TO_FOA(FileAddress, Data_RVA, &Data_FOA);
				if (ret != 0)
				{
					printf("func RVA_TO_FOA() Error!\n");
					return ret;
				}

				//(4)获取需要重定位的数据
				PDWORD RelocationData = (PDWORD)((DWORD)FileAddress + Data_FOA);

				printf("第[%04X]项    |数据 :[%04X]   |数据的RVA :[%08X]  |数据属性 :[%X]  |重定位数据  :[%08X]\n", i+1, BlockData, Data_RVA, (DataGroup[i] >> 12), *RelocationData);
			}
		}
		
		printf("================= BlockData End ========================\n");
	
		//指向下一个数据块
		RelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)RelocationDirectory + RelocationDirectory->SizeOfBlock);
	}


	return ret;
}


int main09()
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

	//2、打印重定位表信息
	ret = PrintReloactionTable(FileAddress);
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





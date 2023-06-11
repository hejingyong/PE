# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"

# define NEW_FILE "C:/Users/Qiu_JY/Desktop/Out.exe"

/*
1、改变EXE文件中的ImageBase，然后手动修复重定位表，使其能够正常运行。(EXE文件必须包含重定位表，否则会失败)
*/

int ChangeRelocationTable(PVOID FileAddress, PDWORD FileLength)
{
	
	int ret = 0;
	DWORD NewImageBase = 0;
	DWORD OldImageBase = 0;

	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2、修改ImageBase
	OldImageBase = pOptionalHeader->ImageBase;
	PDWORD pImageBase = &pOptionalHeader->ImageBase;
	*pImageBase = *pImageBase + 0x100000;
	NewImageBase = *pImageBase;

	//3、获取重定位表的地址
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

	//4、指向重定位表
	PIMAGE_BASE_RELOCATION RelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)FileAddress + RelocationDirectory_FOAAdd);

	//5、修复重定位表
	while (RelocationDirectory->VirtualAddress && RelocationDirectory->SizeOfBlock)
	{
		//	1)计算在当前块中的数据个数
		DWORD DataNumber = (RelocationDirectory->SizeOfBlock - 8) / 2;

		//	2)指向数据块
		PWORD DataGroup = (PWORD)((DWORD)RelocationDirectory + 8);

		//	3)循环修复重定位数据
		for (DWORD i = 0; i < DataNumber; i++)
		{
			//	4)判断高4位是否为0
			if (DataGroup[i] >> 12 != 0)
			{
				//	5)提取数据块中的有效数据 低12位
				WORD BlockData = DataGroup[i] & 0xFFF;

				//	6)计算数据块的RVA和FOA
				DWORD Data_RVA = RelocationDirectory->VirtualAddress + BlockData;
				DWORD Data_FOA = 0;
				ret = RVA_TO_FOA(FileAddress, Data_RVA, &Data_FOA);
				if (ret != 0)
				{
					printf("func RVA_TO_FOA() Error!\n");
					return ret;
				}

				//	7)获取需要重定位的数据
				PDWORD pRelocationData = (PDWORD)((DWORD)FileAddress + Data_FOA);

				//	8)修正数据
				*pRelocationData = *pRelocationData - OldImageBase + NewImageBase;
			}
		}
		//	9)指向下一个数据块
		RelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)RelocationDirectory + RelocationDirectory->SizeOfBlock);
	}

	//6、获取文件长度
	FILE *pf = fopen(FILE_PATH, "rb");
	if (pf == NULL)
	{
		ret = -1;
		printf("func fopen() Error: %d\n", ret);
		return ret;
	}
	ret = GetFileLength(pf, FileLength);
	if (ret != 0 && *FileLength == -1)
	{
		ret = -2;
		printf("func GetFileLength() Error!\n");
		return ret;
	}
	fclose(pf);

	return ret;
}


int main11()
{
	int ret = 0;
	PVOID FileAddress = NULL;
	DWORD FileLength = 0;

	//1、将文件读入到内存   
	ret = MyReadFile(&FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//2、修改ImageBase，随后修正重定位表
	ret = ChangeRelocationTable(FileAddress, &FileLength);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//3、将文件写入内存
	ret = MyWriteFile(FileAddress, FileLength, NEW_FILE);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}
	if (FileAddress != NULL)
		free(FileAddress);

	return ret;
}

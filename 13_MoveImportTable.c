# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"


# define NEW_FILE "C:/Users/Qiu_JY/Desktop/Out.exe"

/*
1、在PE文件中创建一个新节，然后将导入表、INT表移动到新节中。最后将文件写入硬盘，并可以正确解析导入表。
   由于IAT表的地址在程序中写死，所以无法移动IAT表
*/


//添加节的主要操作
int AddSection_V3(PVOID FileAddress, PVOID *NewFileAddress, PDWORD pNewLength)
{
	int ret = 0;

	DWORD OldLength = 0;
	DWORD NewLength = 0;
	DWORD RemainingSpace = 0;	//	剩余空间
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionGroup = NULL;
	PIMAGE_SECTION_HEADER pLastSection = NULL;

	//Add_指向相关内容
	pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//Add_判断导入表是否存在
	if (pOptionalHeader->DataDirectory[1].VirtualAddress == 0)
	{
		ret = -7;
		printf("RelocationDirectory 不存在!\n");
		return ret;
	}


	//1、进行扩展空间
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

	//Change_将旧的空间增加合适的大小，由导入表和IAT表大小 和INT表的大小名字长度决定节的大小(为了方便直接多分配0x5000个大小)
	NewLength = OldLength + 0x1000 + (pOptionalHeader->DataDirectory[1].Size / 0x1000 * 0x1000 + 0x5000);
	*NewFileAddress = (LPVOID)malloc(NewLength);
	if (*NewFileAddress == NULL)
	{
		ret = -3;
		printf("func malloc() Error!\n");
		return ret;
	}
	memset(*NewFileAddress, 0, NewLength);

	//2、将旧空间的内容copy到新的空间
	memcpy(*NewFileAddress, FileAddress, OldLength);

	//3、将指针指向对应位置
	pDosHeader = (PIMAGE_DOS_HEADER)(*NewFileAddress);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	pLastSection = &pSectionGroup[pFileHeader->NumberOfSections - 1];

	//4、判断是否有足够的内存空间
	RemainingSpace = pOptionalHeader->SizeOfHeaders -
		pDosHeader->e_lfanew - 4 -
		sizeof(IMAGE_FILE_HEADER) -
		pFileHeader->SizeOfOptionalHeader -
		sizeof(IMAGE_SECTION_HEADER) * pFileHeader->NumberOfSections;

	if (RemainingSpace < 2 * sizeof(IMAGE_SECTION_HEADER))
	{
		ret = -5;
		printf("文件头剩余空间不足，无法进行添加节区操作");
		return ret;
	}

	//5、修改相关内容 需要用更高级的指针进行操作
	LPWORD pNumberOfSections = &pFileHeader->NumberOfSections;
	LPDWORD pSizeOfImage = &pOptionalHeader->SizeOfImage;

	PVOID pSecName = &pSectionGroup[pFileHeader->NumberOfSections].Name;
	LPDWORD pSecMisc = &pSectionGroup[pFileHeader->NumberOfSections].Misc.VirtualSize;
	LPDWORD pSecVirtualAddress = &pSectionGroup[pFileHeader->NumberOfSections].VirtualAddress;
	LPDWORD pSecSizeOfRawData = &pSectionGroup[pFileHeader->NumberOfSections].SizeOfRawData;
	LPDWORD pSecPointerToRawData = &pSectionGroup[pFileHeader->NumberOfSections].PointerToRawData;
	LPDWORD pSecCharacteristics = &pSectionGroup[pFileHeader->NumberOfSections].Characteristics;

	*pNumberOfSections = pFileHeader->NumberOfSections + 1;
	//Change_修改大小
	*pSizeOfImage = pOptionalHeader->SizeOfImage + NewLength - OldLength;

	memcpy(pSecName, ".NewSec", 8);
	//Change_修改大小
	*pSecMisc = NewLength - OldLength;
	*pSecVirtualAddress = pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize;
	//SectionAlignment对齐
	if (*pSecVirtualAddress % pOptionalHeader->SectionAlignment)
	{
		*pSecVirtualAddress = (*pSecVirtualAddress) / pOptionalHeader->SectionAlignment * pOptionalHeader->SectionAlignment + pOptionalHeader->SectionAlignment;
	}
	//Change_修改大小
	*pSecSizeOfRawData = NewLength - OldLength;

	*pSecPointerToRawData = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;
	//FileAlignment对齐
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

	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pLastSection = &pSectionGroup[pFileHeader->NumberOfSections - 1]; //最后一个节的属性

	//2、获取导入表的地址
	DWORD ImportDirectory_RAVAdd = pOptionalHeader->DataDirectory[1].VirtualAddress;
	DWORD ImportDirectory_FOAAdd = 0;
	//	(1)、判断导入表是否存在
	if (ImportDirectory_RAVAdd == 0)
	{
		printf("RelocationDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取导入表的FOA地址
	ret = RVA_TO_FOA(FileAddress, ImportDirectory_RAVAdd, &ImportDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//3、指向导入表
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)FileAddress + ImportDirectory_FOAAdd);

	//4、获取最后一个节的地址作为拷贝目标地址
	PVOID NextAddress = (PVOID)((DWORD)FileAddress + pLastSection->PointerToRawData);

	//5、指向新的导入表地址
	PIMAGE_IMPORT_DESCRIPTOR NewImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)FileAddress + pLastSection->PointerToRawData);

	//6、循环拷贝数据
	//	1)先将所有的导入表移动到新节
	DWORD NewImportTableAddress_RVA = 0;
	DWORD NewImportTableAddress_FOA = ((DWORD)NextAddress - (DWORD)FileAddress);
	memcpy(NextAddress, ImportDirectory, pOptionalHeader->DataDirectory[1].Size);	//
	ret = FOA_TO_RVA(FileAddress, NewImportTableAddress_FOA, &NewImportTableAddress_RVA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//	2)将指针移动到下一个空白地址
	NextAddress = (PDWORD)((DWORD)NextAddress + pOptionalHeader->DataDirectory[1].Size);

	
	while (NewImportDirectory->FirstThunk && NewImportDirectory->OriginalFirstThunk)
	{
		//	3)指向INT表
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
		
		//	4)计算新的INT表的RVA
		ret = FOA_TO_RVA(FileAddress, NewOriginalFirstThunk_FOA, &NewOriginalFirstThunk_RVA);
		if (ret != 0)
		{
			printf("func FOA_TO_RVA() Error!\n");
			return ret;
		}

		//	5)获取INT表中项目的个数
		DWORD NumberOfThunk = 0;
		while (*OriginalFirstThunk)
		{
			NumberOfThunk++;
			OriginalFirstThunk++;
		}
		NumberOfThunk++;	//加上最后一个空白结构
		OriginalFirstThunk = (PDWORD)((DWORD)FileAddress + OriginalFirstThunk_FOA);

		//	6)把INT表移动过来
		memcpy(NextAddress, OriginalFirstThunk, 4 * NumberOfThunk);

		//	7)将指针移动到下一个空白地址
		NextAddress = (PVOID)((DWORD)NextAddress + 4 * NumberOfThunk);
		
		//	8)循环INT表
		while (*NewOriginalFirstThunk)
		{
			//	9)判断INT表的内容  
			if ((*NewOriginalFirstThunk >> 31) == 0)	//名字导入 
			{
				//	10)获取函数名
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

				//	11)获取导入名字结构体的大小
				DWORD SizeOfImportByName = 3 + strlen(ImportName->Name);

				//	12)计算导入名字结构体的RVA
				ret = FOA_TO_RVA(FileAddress, NewImportNameAdd_FOA, &NewImportNameAdd_RVA);
				if (ret != 0)
				{
					printf("func FOA_TO_RVA() Error!\n");
					return ret;
				}

				//	13)将导入名字结构体移动
				memcpy(NextAddress, ImportName, SizeOfImportByName);

				//	14)修正INT表
				*NewOriginalFirstThunk = NewImportNameAdd_RVA;

				//	15)将指针移动到下一个空白地址	下一个IMAGE_IMPORT_BY_NAME
				NextAddress = (PVOID)((DWORD)NextAddress + SizeOfImportByName);
			}

			//	16)指向下一个INT
			*NewOriginalFirstThunk++;
		}

		//	17)获取导入文件名
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

		//	18)计算新的导入文件名RVA
		ret = FOA_TO_RVA(FileAddress, NewNameAdd_FOA, &NewNameAdd_RVA);
		if (ret != 0)
		{
			printf("func FOA_TO_RVA() Error!\n");
			return ret;
		}
		
		//	19)获取导入文件名的长度
		DWORD FileNameLength = strlen(ImportName) + 1;

		//	20)将导入文件名移动到新节
		memcpy(NextAddress, ImportName, FileNameLength);

		//	21)指向下一个空余地址
		NextAddress = (PVOID)((DWORD)NextAddress + FileNameLength);

		//	22)修正新的导入表
		PDWORD pOriginalFirstThunk = &NewImportDirectory->OriginalFirstThunk;
		PDWORD pName = &NewImportDirectory->Name;

		*pOriginalFirstThunk = NewOriginalFirstThunk_RVA;
		*pName = NewNameAdd_RVA;

		//	23)将导入表指针后移
		NewImportDirectory++;
	}

	//7、修复目录项
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

	//1、将文件读入到内存   
	ret = MyReadFile(&FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//2、在文件中添加一个节区  copy之前的代码并将节区的大小做了小的修改
	ret = AddSection_V3(FileAddress, &NewFileAddress, &NewFileLength);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		if (NewFileAddress != NULL)
			free(NewFileAddress);
		return ret;
	}
	
	//3、移动导出表 到最后一个节区
	ret = MoveImportTable(NewFileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		if (NewFileAddress != NULL)
			free(NewFileAddress);
		return ret;
	}


	//4、将文件写入内存
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
# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"

# define NEW_FILE "C:/Users/Qiu_JY/Desktop/Out.exe"

/*
1、在PE文件中创建一个新节，然后将导出表的所有信息移动到新节中。最后将文件写入硬盘，并可以正确解析导出表。
*/

//添加节的主要操作
int AddSection_V1(PVOID FileAddress, PVOID *NewFileAddress, PDWORD pNewLength)
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

	//Add_判断导出表是否存在
	if (pOptionalHeader->DataDirectory[0].VirtualAddress == 0)
	{
		ret = -7;
		printf("ExportDirectory 不存在!\n");
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

	//Change_将旧的空间增加合适的大小，由导出表大小决定最后4k对齐。
	NewLength = OldLength + 0x1000 + (pOptionalHeader->DataDirectory[0].Size / 0x1000 * 0x1000);
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


int MoveExportTable(PVOID FileAddress)
{
	int ret = 0;
	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pLastSection = &pSectionGroup[pFileHeader->NumberOfSections - 1]; //最后一个节的属性

	//	指向最后一个节
	PVOID pLastSectionAddress = (PVOID)((DWORD)FileAddress + pLastSection->PointerToRawData);


	//2、获取导出表的地址
	DWORD ExportDirectory_RAVAdd = pOptionalHeader->DataDirectory[0].VirtualAddress;
	DWORD ExportDirectory_FOAAdd = 0;
	//	(1)、判断导出表是否存在
	if (ExportDirectory_RAVAdd == 0)
	{
		printf("ExportDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取导出表的FOA地址
	ret = RVA_TO_FOA(FileAddress, ExportDirectory_RAVAdd, &ExportDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//3、指向导出表
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)FileAddress + ExportDirectory_FOAAdd);

	//4、首先移动函数地址表
	//	1)找到函数地址表
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

	//	2)将函数地址表拷贝到新节区
	memcpy(pLastSectionAddress, (PVOID)((DWORD)FileAddress + AddressOfFunctions_FOA), 4 * ExportDirectory->NumberOfFunctions);
	
	//	3)计算新的RVA
	NewAddressOfFunction_FOA = pLastSection->PointerToRawData;
	ret = FOA_TO_RVA(FileAddress, NewAddressOfFunction_FOA, &NewAddressOfFunction_RVA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//	4)获取下一个空余地址
	PVOID NextAddress = (PVOID)((DWORD)pLastSectionAddress + 4 * ExportDirectory->NumberOfFunctions);

	//5、移动函数序号表
	//	1)找到函数序号表
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

	//	2)将函数序号表拷贝到新节区
	memcpy(NextAddress, (PVOID)((DWORD)FileAddress + AddressOfOrdinal_FOA), 2 * ExportDirectory->NumberOfNames);
	
	//	3)计算新的RVA
	NewAddressOfOrdinal_FOA = NewAddressOfFunction_FOA + 4 * ExportDirectory->NumberOfFunctions;
	ret = FOA_TO_RVA(FileAddress, NewAddressOfOrdinal_FOA, &NewAddressOfOrdinal_RVA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//	4)获取下一个空余地址
	NextAddress = (PVOID)((DWORD)NextAddress + 2 * ExportDirectory->NumberOfNames);

	//6、移动函数名称表
	//	1)找到函数名称表
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

	//	2)将函数序号表拷贝到新节区
	memcpy(NextAddress, (PVOID)((DWORD)FileAddress + AddressOfName_FOA), 4 * ExportDirectory->NumberOfNames);

	//	3)计算新的RVA
	NewAddressOfName_FOA = NewAddressOfOrdinal_FOA + 2 * ExportDirectory->NumberOfNames;
	ret = FOA_TO_RVA(FileAddress, NewAddressOfName_FOA, &NewAddressOfName_RVA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//	4)获取下一个空余地址
	NextAddress = (PVOID)((DWORD)NextAddress + 4 * ExportDirectory->NumberOfNames);

	//7、循环拷贝函数名，顺带修复函数名表
	//	1)指向新的函数名表
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

		//	2)找到函数名
		PCHAR FuncName = (PCHAR)((DWORD)FileAddress + FuncName_FOA);
		
		//	3)计算函数名长度
		DWORD FuncNameLength = strlen(FuncName) + 1;

		//	4)拷贝函数名
		memcpy(NextAddress, FuncName, FuncNameLength);

		//	5)计算新的函数名地址RVA
		NewFuncName_FOA = (DWORD)NextAddress - (DWORD)FileAddress;
		ret = FOA_TO_RVA(FileAddress, NewFuncName_FOA, &NewFuncName_RVA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}

		//	6)修正函数名表
		pFunctionNameTable[i] = NewFuncName_RVA;

		//	7)计算下一个空余地址
		NextAddress = (PVOID)((DWORD)NextAddress + FuncNameLength);
	}

	//8、拷贝文件名
	//	1)找到文件名
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

	//	2)计算文件名长度
	DWORD FileNameLength = strlen(FileName) + 1;

	//	3)拷贝文件名
	memcpy(NextAddress, FileName, FileNameLength);

	//	4)计算新的文件名地址RVA
	NewFileName_FOA = (DWORD)NextAddress - (DWORD)FileAddress;
	ret = FOA_TO_RVA(FileAddress, NewFileName_FOA, &NewFileName_RVA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//	5)计算下一个空余地址
	NextAddress = (PVOID)((DWORD)NextAddress + FileNameLength);

	//9、拷贝导出表结构体
	DWORD NewExportDirectory_RAVAdd = 0;
	DWORD NewExportDirectory_FOAAdd = 0;

	//	1)拷贝导出表
	memcpy(NextAddress, ExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY));

	//	2)计算新的导出表地址RVA
	NewExportDirectory_FOAAdd = (DWORD)NextAddress - (DWORD)FileAddress;
	ret = FOA_TO_RVA(FileAddress, NewExportDirectory_FOAAdd, &NewExportDirectory_RAVAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//10、修复导出表中的值
	//	1)指向新的导出表
	PIMAGE_EXPORT_DIRECTORY pNewExportDirectory = NextAddress;
	
	//	2)指向需要修改的数据
	PDWORD pExportName = &pNewExportDirectory->Name;
	PDWORD pExportAddressOfFunctions = &pNewExportDirectory->AddressOfFunctions;
	PDWORD pExportAddressOfNameOrdinals = &pNewExportDirectory->AddressOfNameOrdinals;
	PDWORD pExportAddressOfNames = &pNewExportDirectory->AddressOfNames;

	//	3)修改数据
	*pExportName = NewFileName_RVA;
	*pExportAddressOfFunctions = NewAddressOfFunction_RVA;
	*pExportAddressOfNameOrdinals = NewAddressOfOrdinal_RVA;
	*pExportAddressOfNames = NewAddressOfName_RVA;

	//11、修复目录项的地址
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

	//1、将文件读入到内存   
	ret = MyReadFile(&FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//2、在文件中添加一个节区  copy之前的代码并将节区的大小做了小的修改
	ret = AddSection_V1(FileAddress, &NewFileAddress, &NewFileLength);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		if (NewFileAddress != NULL)
			free(NewFileAddress);
		return ret;
	}

	//3、移动导出表 到最后一个节区
	ret = MoveExportTable(NewFileAddress);
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
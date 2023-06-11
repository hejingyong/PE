# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"

# define NEW_FILE "C:/Users/Qiu_JY/Desktop/Out.exe"

/*
1、在PE文件中创建一个新节，然后将重定位表的所有信息移动到新节中。最后将文件写入硬盘，并可以正确解析重定位表。
*/


//添加节的主要操作
int AddSection_V2(PVOID FileAddress, PVOID *NewFileAddress, PDWORD pNewLength)
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

	//Add_判断重定位表是否存在
	if (pOptionalHeader->DataDirectory[5].VirtualAddress == 0)
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

	//Change_将旧的空间增加合适的大小，由导出表大小决定最后4k对齐。
	NewLength = OldLength + 0x1000 + (pOptionalHeader->DataDirectory[5].Size / 0x1000 * 0x1000);
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


int MoveRelocationTable(PVOID FileAddress)
{
	int ret = 0;

	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pLastSection = &pSectionGroup[pFileHeader->NumberOfSections - 1]; //最后一个节的属性

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

	//4、获取最后一个节的地址作为拷贝目标地址
	PVOID NextAddress = (PVOID)((DWORD)FileAddress + pLastSection->PointerToRawData);

	//5、将重定位表循环移动到最后一个节中
	while (RelocationDirectory->VirtualAddress && RelocationDirectory->SizeOfBlock)
	{
		//	(1)将重定位块copy到目标地址
		memcpy(NextAddress, RelocationDirectory, RelocationDirectory->SizeOfBlock);

		//	(2)将目标地址后移
		NextAddress = (PVOID)((DWORD)NextAddress + RelocationDirectory->SizeOfBlock);
		
		//	(3)将旧重定位表块后移
		RelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)RelocationDirectory + RelocationDirectory->SizeOfBlock);
	}

	//6、修复目录项的地址
	PDWORD pVirtualAddress = &pOptionalHeader->DataDirectory[5].VirtualAddress;
	*pVirtualAddress = pLastSection->VirtualAddress;

	return ret;
}

int main10()
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
	ret = AddSection_V2(FileAddress, &NewFileAddress, &NewFileLength);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		if (NewFileAddress != NULL)
			free(NewFileAddress);
		return ret;
	}

	//3、移动导出表 到最后一个节区
	ret = MoveRelocationTable(NewFileAddress);
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
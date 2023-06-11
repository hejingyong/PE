# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"


# define NEW_FILE "C:/Users/Qiu_JY/Desktop/Out.exe"

/*
1、在PE文件中创建一个新节，然后将资源表移动到新节中。最后将文件写入硬盘，并可以正确解析资源表。
*/


//添加节的主要操作
int AddSection_V4(PVOID FileAddress, PVOID *NewFileAddress, PDWORD pNewLength)
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

	//Add_判断资源表是否存在
	if (pOptionalHeader->DataDirectory[2].VirtualAddress == 0)
	{
		ret = -7;
		printf("ResourceDirectory 不存在!\n");
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
	NewLength = OldLength + 0x1000 + (pOptionalHeader->DataDirectory[2].Size / 0x1000 * 0x1000);
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


int MoveResourceTable(PVOID FileAddress)
{
	int ret = 0;
	//1、指向相关内容
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pLastSection = &pSectionGroup[pFileHeader->NumberOfSections - 1]; //最后一个节的属性

	//2、获取资源表的地址
	DWORD ResourceDirectory_RAVAdd = pOptionalHeader->DataDirectory[2].VirtualAddress;
	DWORD ResourceDirectory_FOAAdd = 0;
	//	(1)、判断资源表是否存在
	if (ResourceDirectory_RAVAdd == 0)
	{
		printf("ResourceDirectory 不存在!\n");
		return ret;
	}
	//	(2)、获取资源表的FOA地址
	ret = RVA_TO_FOA(FileAddress, ResourceDirectory_RAVAdd, &ResourceDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//3、指向资源表
	PIMAGE_RESOURCE_DIRECTORY ResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)FileAddress + ResourceDirectory_FOAAdd);

	//4、指向新的资源表地址
	PIMAGE_RESOURCE_DIRECTORY NewResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)FileAddress + pLastSection->PointerToRawData);

	//5、将资源表的一级目录全部copy到新节
	DWORD NewResourceTableAddress_RVA = 0;
	DWORD NewResourceTableAddress_FOA = pLastSection->PointerToRawData;
	//	1)计算一级目录的大小
	DWORD SizeOfResource_Fir = sizeof(IMAGE_RESOURCE_DIRECTORY) + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * (ResourceDirectory->NumberOfNamedEntries + ResourceDirectory->NumberOfIdEntries);
	memcpy(NewResourceDirectory, ResourceDirectory, SizeOfResource_Fir);
	//	2)获取新的RVA地址
	ret = FOA_TO_RVA(FileAddress, NewResourceTableAddress_FOA, &NewResourceTableAddress_RVA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//6、循环一级资源表信息
	//	(1)指向一级目录中的资源目录项(一级目录)	资源类型
	PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirectoryEntry_Fir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)ResourceDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY));
	PIMAGE_RESOURCE_DIRECTORY_ENTRY NewResourceDirectoryEntry_Fir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)NewResourceDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY));


	//	(2)进行循环
	for (int i = 0; i < (ResourceDirectory->NumberOfIdEntries + ResourceDirectory->NumberOfNamedEntries); i++)
	{
		//	(3)判断一级目录中的资源目录项中类型是否是字符串 
		if (ResourceDirectoryEntry_Fir->NameIsString)		//如果是字符串则将名字copy到指定位置，否则不需要操作
		{
			//		1.指向名字结构体
			PIMAGE_RESOURCE_DIR_STRING_U pStringName = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Fir->NameOffset);

			//		2.将字符串copy到指定位置
			DWORD SizeOfNameStruct = sizeof(WORD) * (pStringName->Length + 1);
			memcpy((PVOID)((DWORD)NewResourceDirectory + NewResourceDirectoryEntry_Fir->NameOffset), pStringName, SizeOfNameStruct);
		}

		//	(3)判断一级目录中子节点的类型		1 = 目录； 0 = 数据 (一级目录和二级目录该值都为1)
		if (ResourceDirectoryEntry_Fir->DataIsDirectory)
		{
			//	(4)指向二级目录	资源编号
			PIMAGE_RESOURCE_DIRECTORY ResourceDirectory_Sec = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Fir->OffsetToDirectory);
			PIMAGE_RESOURCE_DIRECTORY NewResourceDirectory_Sec = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)NewResourceDirectory + NewResourceDirectoryEntry_Fir->OffsetToDirectory);

			//	(5)将二级目录copy到指定位置
			DWORD SizeOfResource_Sec = sizeof(IMAGE_RESOURCE_DIRECTORY) + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * (ResourceDirectory_Sec->NumberOfNamedEntries + ResourceDirectory_Sec->NumberOfIdEntries);
			memcpy(NewResourceDirectory_Sec, ResourceDirectory_Sec, SizeOfResource_Sec);
			
			//	(6)指向二级目录中的资源目录项(二级目录)	资源编号
			PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirectoryEntry_Sec = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)ResourceDirectory_Sec + sizeof(IMAGE_RESOURCE_DIRECTORY));
			PIMAGE_RESOURCE_DIRECTORY_ENTRY NewResourceDirectoryEntry_Sec = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)NewResourceDirectory_Sec + sizeof(IMAGE_RESOURCE_DIRECTORY));

			//	(7)进行循环
			for (int j = 0; j < (ResourceDirectory_Sec->NumberOfIdEntries + ResourceDirectory_Sec->NumberOfNamedEntries); j++)
			{
				//	(8)判断二级目录中的资源目录项中类型是否是字符串 
				if (ResourceDirectoryEntry_Sec->NameIsString)
				{
					//		1.指向名字结构体
					PIMAGE_RESOURCE_DIR_STRING_U pStringName = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)ResourceDirectory_Sec + ResourceDirectoryEntry_Sec->NameOffset);

					//		2.将字符串copy到指定位置
					DWORD SizeOfNameStruct = sizeof(WORD) * (pStringName->Length + 1);
					memcpy((PVOID)((DWORD)NewResourceDirectory_Sec + NewResourceDirectoryEntry_Sec->NameOffset), pStringName, SizeOfNameStruct);
				}

				//	(9)判断二级目录中子节点的类型
				if (ResourceDirectoryEntry_Sec->DataIsDirectory)
				{
					//	(10)指向三级目录	代码页
					PIMAGE_RESOURCE_DIRECTORY ResourceDirectory_Thir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Sec->OffsetToDirectory);
					PIMAGE_RESOURCE_DIRECTORY NewResourceDirectory_Thir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)NewResourceDirectory + NewResourceDirectoryEntry_Sec->OffsetToDirectory);

					//	(11)将三级目录copy到指定位置
					DWORD SizeOfResource_Thir = sizeof(IMAGE_RESOURCE_DIRECTORY) + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * (ResourceDirectory_Thir->NumberOfNamedEntries + ResourceDirectory_Thir->NumberOfIdEntries);
					memcpy(NewResourceDirectory_Thir, ResourceDirectory_Thir, SizeOfResource_Thir);

					//	(12)指向三级目录中的资源目录项(三级目录)	代码页
					PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirectoryEntry_Thir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)ResourceDirectory_Thir + sizeof(IMAGE_RESOURCE_DIRECTORY));
					PIMAGE_RESOURCE_DIRECTORY_ENTRY NewResourceDirectoryEntry_Thir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)NewResourceDirectory_Thir + sizeof(IMAGE_RESOURCE_DIRECTORY));

					//	(13)进行循环
					for (int k = 0; k < (ResourceDirectory_Thir->NumberOfIdEntries + ResourceDirectory_Thir->NumberOfNamedEntries); k++)
					{
						//	(14)判断三级目录中资源目录项中类型是否是字符串 
						if (ResourceDirectoryEntry_Thir->NameIsString)
						{
							//		1.指向名字结构体
							PIMAGE_RESOURCE_DIR_STRING_U pStringName = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)ResourceDirectory_Thir + ResourceDirectoryEntry_Thir->NameOffset);

							//		2.将字符串copy到指定位置
							DWORD SizeOfNameStruct = sizeof(WORD) * (pStringName->Length + 1);
							memcpy((PVOID)((DWORD)NewResourceDirectory_Thir + NewResourceDirectoryEntry_Thir->NameOffset), pStringName, SizeOfNameStruct);
						}

						//	(15)判断三级目录中子节点的类型		(三级目录子节点都是数据，这里可以省去判断)
						if (!ResourceDirectoryEntry_Thir->DataIsDirectory)
						{
							//	(16)指向数据内容	(资源表的FOA + OffsetToData)
							PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Thir->OffsetToData);
							PIMAGE_RESOURCE_DATA_ENTRY NewResourceDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)NewResourceDirectory + NewResourceDirectoryEntry_Thir->OffsetToData);

							//	(17)拷贝结构体
							memcpy(NewResourceDataEntry, ResourceDataEntry, sizeof(IMAGE_RESOURCE_DATA_ENTRY));

							//	(18)拷贝资源
							//		1.计算资源RVA偏移
							DWORD NewOffsetToData_RVA = ResourceDataEntry->OffsetToData - (DWORD)ResourceDirectory + (DWORD)NewResourceDirectory;
							DWORD NewOffsetToData_FOA = 0;
							DWORD OffsetToData_RVA = ResourceDataEntry->OffsetToData;
							DWORD OffsetToData_FOA = 0;

							//		2.计算资源FOA偏移
							ret = RVA_TO_FOA(FileAddress, NewOffsetToData_RVA, &NewOffsetToData_FOA);
							if (ret != 0)
							{
								printf("func RVA_TO_FOA() Error!\n");
								return ret;
							}
							ret = RVA_TO_FOA(FileAddress, OffsetToData_RVA, &OffsetToData_FOA);
							if (ret != 0)
							{
								printf("func RVA_TO_FOA() Error!\n");
								return ret;
							}

							//		3.Copy资源数据
							memcpy((PVOID)((DWORD)FileAddress + NewOffsetToData_FOA), (PVOID)((DWORD)FileAddress + OffsetToData_FOA), ResourceDataEntry->Size);

							//		4.修改偏移
							PDWORD pNewOffsetToData = &NewResourceDataEntry->OffsetToData;
							*pNewOffsetToData = NewOffsetToData_RVA;
						}

						ResourceDirectoryEntry_Thir++;
						NewResourceDirectoryEntry_Thir++;
					}
				}

				ResourceDirectoryEntry_Sec++;
				NewResourceDirectoryEntry_Sec++;
			}
		}

		ResourceDirectoryEntry_Fir++;
		NewResourceDirectoryEntry_Fir++;
	}

	//7、修改对应目录项的地址
	PDWORD VirtualAddress = &pOptionalHeader->DataDirectory[2].VirtualAddress;
	*VirtualAddress = NewResourceTableAddress_RVA;

	return ret;
}


int main16()
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
	ret = AddSection_V4(FileAddress, &NewFileAddress, &NewFileLength);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		if (NewFileAddress != NULL)
			free(NewFileAddress);
		return ret;
	}

	//3、移动资源表 到最后一个节区
	ret = MoveResourceTable(NewFileAddress);
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

	system("pause");
	return ret;
}
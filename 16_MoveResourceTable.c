# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"


# define NEW_FILE "C:/Users/Qiu_JY/Desktop/Out.exe"

/*
1����PE�ļ��д���һ���½ڣ�Ȼ����Դ���ƶ����½��С�����ļ�д��Ӳ�̣���������ȷ������Դ��
*/


//��ӽڵ���Ҫ����
int AddSection_V4(PVOID FileAddress, PVOID *NewFileAddress, PDWORD pNewLength)
{
	int ret = 0;

	DWORD OldLength = 0;
	DWORD NewLength = 0;
	DWORD RemainingSpace = 0;	//	ʣ��ռ�
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionGroup = NULL;
	PIMAGE_SECTION_HEADER pLastSection = NULL;

	//Add_ָ���������
	pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//Add_�ж���Դ���Ƿ����
	if (pOptionalHeader->DataDirectory[2].VirtualAddress == 0)
	{
		ret = -7;
		printf("ResourceDirectory ������!\n");
		return ret;
	}

	//1��������չ�ռ�
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

	//Change_���ɵĿռ����Ӻ��ʵĴ�С���ɵ�����IAT���С ��INT��Ĵ�С���ֳ��Ⱦ����ڵĴ�С(Ϊ�˷���ֱ�Ӷ����0x5000����С)
	NewLength = OldLength + 0x1000 + (pOptionalHeader->DataDirectory[2].Size / 0x1000 * 0x1000);
	*NewFileAddress = (LPVOID)malloc(NewLength);
	if (*NewFileAddress == NULL)
	{
		ret = -3;
		printf("func malloc() Error!\n");
		return ret;
	}
	memset(*NewFileAddress, 0, NewLength);

	//2�����ɿռ������copy���µĿռ�
	memcpy(*NewFileAddress, FileAddress, OldLength);

	//3����ָ��ָ���Ӧλ��
	pDosHeader = (PIMAGE_DOS_HEADER)(*NewFileAddress);
	pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	pLastSection = &pSectionGroup[pFileHeader->NumberOfSections - 1];

	//4���ж��Ƿ����㹻���ڴ�ռ�
	RemainingSpace = pOptionalHeader->SizeOfHeaders -
		pDosHeader->e_lfanew - 4 -
		sizeof(IMAGE_FILE_HEADER) -
		pFileHeader->SizeOfOptionalHeader -
		sizeof(IMAGE_SECTION_HEADER) * pFileHeader->NumberOfSections;

	if (RemainingSpace < 2 * sizeof(IMAGE_SECTION_HEADER))
	{
		ret = -5;
		printf("�ļ�ͷʣ��ռ䲻�㣬�޷�������ӽ�������");
		return ret;
	}

	//5���޸�������� ��Ҫ�ø��߼���ָ����в���
	LPWORD pNumberOfSections = &pFileHeader->NumberOfSections;
	LPDWORD pSizeOfImage = &pOptionalHeader->SizeOfImage;

	PVOID pSecName = &pSectionGroup[pFileHeader->NumberOfSections].Name;
	LPDWORD pSecMisc = &pSectionGroup[pFileHeader->NumberOfSections].Misc.VirtualSize;
	LPDWORD pSecVirtualAddress = &pSectionGroup[pFileHeader->NumberOfSections].VirtualAddress;
	LPDWORD pSecSizeOfRawData = &pSectionGroup[pFileHeader->NumberOfSections].SizeOfRawData;
	LPDWORD pSecPointerToRawData = &pSectionGroup[pFileHeader->NumberOfSections].PointerToRawData;
	LPDWORD pSecCharacteristics = &pSectionGroup[pFileHeader->NumberOfSections].Characteristics;

	*pNumberOfSections = pFileHeader->NumberOfSections + 1;
	//Change_�޸Ĵ�С
	*pSizeOfImage = pOptionalHeader->SizeOfImage + NewLength - OldLength;

	memcpy(pSecName, ".NewSec", 8);
	//Change_�޸Ĵ�С
	*pSecMisc = NewLength - OldLength;
	*pSecVirtualAddress = pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize;
	//SectionAlignment����
	if (*pSecVirtualAddress % pOptionalHeader->SectionAlignment)
	{
		*pSecVirtualAddress = (*pSecVirtualAddress) / pOptionalHeader->SectionAlignment * pOptionalHeader->SectionAlignment + pOptionalHeader->SectionAlignment;
	}
	//Change_�޸Ĵ�С
	*pSecSizeOfRawData = NewLength - OldLength;

	*pSecPointerToRawData = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;
	//FileAlignment����
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
	//1��ָ���������
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pLastSection = &pSectionGroup[pFileHeader->NumberOfSections - 1]; //���һ���ڵ�����

	//2����ȡ��Դ��ĵ�ַ
	DWORD ResourceDirectory_RAVAdd = pOptionalHeader->DataDirectory[2].VirtualAddress;
	DWORD ResourceDirectory_FOAAdd = 0;
	//	(1)���ж���Դ���Ƿ����
	if (ResourceDirectory_RAVAdd == 0)
	{
		printf("ResourceDirectory ������!\n");
		return ret;
	}
	//	(2)����ȡ��Դ���FOA��ַ
	ret = RVA_TO_FOA(FileAddress, ResourceDirectory_RAVAdd, &ResourceDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//3��ָ����Դ��
	PIMAGE_RESOURCE_DIRECTORY ResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)FileAddress + ResourceDirectory_FOAAdd);

	//4��ָ���µ���Դ���ַ
	PIMAGE_RESOURCE_DIRECTORY NewResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)FileAddress + pLastSection->PointerToRawData);

	//5������Դ���һ��Ŀ¼ȫ��copy���½�
	DWORD NewResourceTableAddress_RVA = 0;
	DWORD NewResourceTableAddress_FOA = pLastSection->PointerToRawData;
	//	1)����һ��Ŀ¼�Ĵ�С
	DWORD SizeOfResource_Fir = sizeof(IMAGE_RESOURCE_DIRECTORY) + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * (ResourceDirectory->NumberOfNamedEntries + ResourceDirectory->NumberOfIdEntries);
	memcpy(NewResourceDirectory, ResourceDirectory, SizeOfResource_Fir);
	//	2)��ȡ�µ�RVA��ַ
	ret = FOA_TO_RVA(FileAddress, NewResourceTableAddress_FOA, &NewResourceTableAddress_RVA);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//6��ѭ��һ����Դ����Ϣ
	//	(1)ָ��һ��Ŀ¼�е���ԴĿ¼��(һ��Ŀ¼)	��Դ����
	PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirectoryEntry_Fir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)ResourceDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY));
	PIMAGE_RESOURCE_DIRECTORY_ENTRY NewResourceDirectoryEntry_Fir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)NewResourceDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY));


	//	(2)����ѭ��
	for (int i = 0; i < (ResourceDirectory->NumberOfIdEntries + ResourceDirectory->NumberOfNamedEntries); i++)
	{
		//	(3)�ж�һ��Ŀ¼�е���ԴĿ¼���������Ƿ����ַ��� 
		if (ResourceDirectoryEntry_Fir->NameIsString)		//������ַ���������copy��ָ��λ�ã�������Ҫ����
		{
			//		1.ָ�����ֽṹ��
			PIMAGE_RESOURCE_DIR_STRING_U pStringName = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Fir->NameOffset);

			//		2.���ַ���copy��ָ��λ��
			DWORD SizeOfNameStruct = sizeof(WORD) * (pStringName->Length + 1);
			memcpy((PVOID)((DWORD)NewResourceDirectory + NewResourceDirectoryEntry_Fir->NameOffset), pStringName, SizeOfNameStruct);
		}

		//	(3)�ж�һ��Ŀ¼���ӽڵ������		1 = Ŀ¼�� 0 = ���� (һ��Ŀ¼�Ͷ���Ŀ¼��ֵ��Ϊ1)
		if (ResourceDirectoryEntry_Fir->DataIsDirectory)
		{
			//	(4)ָ�����Ŀ¼	��Դ���
			PIMAGE_RESOURCE_DIRECTORY ResourceDirectory_Sec = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Fir->OffsetToDirectory);
			PIMAGE_RESOURCE_DIRECTORY NewResourceDirectory_Sec = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)NewResourceDirectory + NewResourceDirectoryEntry_Fir->OffsetToDirectory);

			//	(5)������Ŀ¼copy��ָ��λ��
			DWORD SizeOfResource_Sec = sizeof(IMAGE_RESOURCE_DIRECTORY) + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * (ResourceDirectory_Sec->NumberOfNamedEntries + ResourceDirectory_Sec->NumberOfIdEntries);
			memcpy(NewResourceDirectory_Sec, ResourceDirectory_Sec, SizeOfResource_Sec);
			
			//	(6)ָ�����Ŀ¼�е���ԴĿ¼��(����Ŀ¼)	��Դ���
			PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirectoryEntry_Sec = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)ResourceDirectory_Sec + sizeof(IMAGE_RESOURCE_DIRECTORY));
			PIMAGE_RESOURCE_DIRECTORY_ENTRY NewResourceDirectoryEntry_Sec = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)NewResourceDirectory_Sec + sizeof(IMAGE_RESOURCE_DIRECTORY));

			//	(7)����ѭ��
			for (int j = 0; j < (ResourceDirectory_Sec->NumberOfIdEntries + ResourceDirectory_Sec->NumberOfNamedEntries); j++)
			{
				//	(8)�ж϶���Ŀ¼�е���ԴĿ¼���������Ƿ����ַ��� 
				if (ResourceDirectoryEntry_Sec->NameIsString)
				{
					//		1.ָ�����ֽṹ��
					PIMAGE_RESOURCE_DIR_STRING_U pStringName = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)ResourceDirectory_Sec + ResourceDirectoryEntry_Sec->NameOffset);

					//		2.���ַ���copy��ָ��λ��
					DWORD SizeOfNameStruct = sizeof(WORD) * (pStringName->Length + 1);
					memcpy((PVOID)((DWORD)NewResourceDirectory_Sec + NewResourceDirectoryEntry_Sec->NameOffset), pStringName, SizeOfNameStruct);
				}

				//	(9)�ж϶���Ŀ¼���ӽڵ������
				if (ResourceDirectoryEntry_Sec->DataIsDirectory)
				{
					//	(10)ָ������Ŀ¼	����ҳ
					PIMAGE_RESOURCE_DIRECTORY ResourceDirectory_Thir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Sec->OffsetToDirectory);
					PIMAGE_RESOURCE_DIRECTORY NewResourceDirectory_Thir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)NewResourceDirectory + NewResourceDirectoryEntry_Sec->OffsetToDirectory);

					//	(11)������Ŀ¼copy��ָ��λ��
					DWORD SizeOfResource_Thir = sizeof(IMAGE_RESOURCE_DIRECTORY) + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * (ResourceDirectory_Thir->NumberOfNamedEntries + ResourceDirectory_Thir->NumberOfIdEntries);
					memcpy(NewResourceDirectory_Thir, ResourceDirectory_Thir, SizeOfResource_Thir);

					//	(12)ָ������Ŀ¼�е���ԴĿ¼��(����Ŀ¼)	����ҳ
					PIMAGE_RESOURCE_DIRECTORY_ENTRY ResourceDirectoryEntry_Thir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)ResourceDirectory_Thir + sizeof(IMAGE_RESOURCE_DIRECTORY));
					PIMAGE_RESOURCE_DIRECTORY_ENTRY NewResourceDirectoryEntry_Thir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)NewResourceDirectory_Thir + sizeof(IMAGE_RESOURCE_DIRECTORY));

					//	(13)����ѭ��
					for (int k = 0; k < (ResourceDirectory_Thir->NumberOfIdEntries + ResourceDirectory_Thir->NumberOfNamedEntries); k++)
					{
						//	(14)�ж�����Ŀ¼����ԴĿ¼���������Ƿ����ַ��� 
						if (ResourceDirectoryEntry_Thir->NameIsString)
						{
							//		1.ָ�����ֽṹ��
							PIMAGE_RESOURCE_DIR_STRING_U pStringName = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)ResourceDirectory_Thir + ResourceDirectoryEntry_Thir->NameOffset);

							//		2.���ַ���copy��ָ��λ��
							DWORD SizeOfNameStruct = sizeof(WORD) * (pStringName->Length + 1);
							memcpy((PVOID)((DWORD)NewResourceDirectory_Thir + NewResourceDirectoryEntry_Thir->NameOffset), pStringName, SizeOfNameStruct);
						}

						//	(15)�ж�����Ŀ¼���ӽڵ������		(����Ŀ¼�ӽڵ㶼�����ݣ��������ʡȥ�ж�)
						if (!ResourceDirectoryEntry_Thir->DataIsDirectory)
						{
							//	(16)ָ����������	(��Դ���FOA + OffsetToData)
							PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)ResourceDirectory + ResourceDirectoryEntry_Thir->OffsetToData);
							PIMAGE_RESOURCE_DATA_ENTRY NewResourceDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)NewResourceDirectory + NewResourceDirectoryEntry_Thir->OffsetToData);

							//	(17)�����ṹ��
							memcpy(NewResourceDataEntry, ResourceDataEntry, sizeof(IMAGE_RESOURCE_DATA_ENTRY));

							//	(18)������Դ
							//		1.������ԴRVAƫ��
							DWORD NewOffsetToData_RVA = ResourceDataEntry->OffsetToData - (DWORD)ResourceDirectory + (DWORD)NewResourceDirectory;
							DWORD NewOffsetToData_FOA = 0;
							DWORD OffsetToData_RVA = ResourceDataEntry->OffsetToData;
							DWORD OffsetToData_FOA = 0;

							//		2.������ԴFOAƫ��
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

							//		3.Copy��Դ����
							memcpy((PVOID)((DWORD)FileAddress + NewOffsetToData_FOA), (PVOID)((DWORD)FileAddress + OffsetToData_FOA), ResourceDataEntry->Size);

							//		4.�޸�ƫ��
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

	//7���޸Ķ�ӦĿ¼��ĵ�ַ
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

	//1�����ļ����뵽�ڴ�   
	ret = MyReadFile(&FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//2�����ļ������һ������  copy֮ǰ�Ĵ��벢�������Ĵ�С����С���޸�
	ret = AddSection_V4(FileAddress, &NewFileAddress, &NewFileLength);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		if (NewFileAddress != NULL)
			free(NewFileAddress);
		return ret;
	}

	//3���ƶ���Դ�� �����һ������
	ret = MoveResourceTable(NewFileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		if (NewFileAddress != NULL)
			free(NewFileAddress);
		return ret;
	}

	//4�����ļ�д���ڴ�
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
# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"

# define NEW_FILE "C:/Users/Qiu_JY/Desktop/Out.exe"

/*
1���ı�EXE�ļ��е�ImageBase��Ȼ���ֶ��޸��ض�λ��ʹ���ܹ��������С�(EXE�ļ���������ض�λ�������ʧ��)
*/

int ChangeRelocationTable(PVOID FileAddress, PDWORD FileLength)
{
	
	int ret = 0;
	DWORD NewImageBase = 0;
	DWORD OldImageBase = 0;

	//1��ָ���������
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2���޸�ImageBase
	OldImageBase = pOptionalHeader->ImageBase;
	PDWORD pImageBase = &pOptionalHeader->ImageBase;
	*pImageBase = *pImageBase + 0x100000;
	NewImageBase = *pImageBase;

	//3����ȡ�ض�λ��ĵ�ַ
	DWORD RelocationDirectory_RAVAdd = pOptionalHeader->DataDirectory[5].VirtualAddress;
	DWORD RelocationDirectory_FOAAdd = 0;
	//	(1)���ж��ض�λ���Ƿ����
	if (RelocationDirectory_RAVAdd == 0)
	{
		printf("RelocationDirectory ������!\n");
		return ret;
	}
	//	(2)����ȡ�ض�λ���FOA��ַ
	ret = RVA_TO_FOA(FileAddress, RelocationDirectory_RAVAdd, &RelocationDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//4��ָ���ض�λ��
	PIMAGE_BASE_RELOCATION RelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)FileAddress + RelocationDirectory_FOAAdd);

	//5���޸��ض�λ��
	while (RelocationDirectory->VirtualAddress && RelocationDirectory->SizeOfBlock)
	{
		//	1)�����ڵ�ǰ���е����ݸ���
		DWORD DataNumber = (RelocationDirectory->SizeOfBlock - 8) / 2;

		//	2)ָ�����ݿ�
		PWORD DataGroup = (PWORD)((DWORD)RelocationDirectory + 8);

		//	3)ѭ���޸��ض�λ����
		for (DWORD i = 0; i < DataNumber; i++)
		{
			//	4)�жϸ�4λ�Ƿ�Ϊ0
			if (DataGroup[i] >> 12 != 0)
			{
				//	5)��ȡ���ݿ��е���Ч���� ��12λ
				WORD BlockData = DataGroup[i] & 0xFFF;

				//	6)�������ݿ��RVA��FOA
				DWORD Data_RVA = RelocationDirectory->VirtualAddress + BlockData;
				DWORD Data_FOA = 0;
				ret = RVA_TO_FOA(FileAddress, Data_RVA, &Data_FOA);
				if (ret != 0)
				{
					printf("func RVA_TO_FOA() Error!\n");
					return ret;
				}

				//	7)��ȡ��Ҫ�ض�λ������
				PDWORD pRelocationData = (PDWORD)((DWORD)FileAddress + Data_FOA);

				//	8)��������
				*pRelocationData = *pRelocationData - OldImageBase + NewImageBase;
			}
		}
		//	9)ָ����һ�����ݿ�
		RelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)RelocationDirectory + RelocationDirectory->SizeOfBlock);
	}

	//6����ȡ�ļ�����
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

	//1�����ļ����뵽�ڴ�   
	ret = MyReadFile(&FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//2���޸�ImageBase����������ض�λ��
	ret = ChangeRelocationTable(FileAddress, &FileLength);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//3�����ļ�д���ڴ�
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

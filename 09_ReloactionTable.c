# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"


/*
1����λ�ض�λ������ӡ���ض�λ���������Լ���Ҫ�ض�λ������
*/


int PrintReloactionTable(PVOID FileAddress)
{
	int ret = 0;

	//1��ָ���������
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2����ȡ�ض�λ��ĵ�ַ
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

	//3��ָ���ض�λ��
	PIMAGE_BASE_RELOCATION RelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)FileAddress + RelocationDirectory_FOAAdd);

	//4��ѭ����ӡ�ض�λ��Ϣ  ��VirtualAddress��SizeOfBlock��Ϊ0ʱ�������
	while (RelocationDirectory->VirtualAddress && RelocationDirectory->SizeOfBlock)
	{
		printf("VirtualAddress    :%08X\n", RelocationDirectory->VirtualAddress);
		printf("SizeOfBlock       :%08X\n", RelocationDirectory->SizeOfBlock);
		printf("================= BlockData Start ======================\n");
		//5�������ڵ�ǰ���е����ݸ���
		DWORD DataNumber = (RelocationDirectory->SizeOfBlock - 8) / 2;

		//6��ָ�����ݿ�
		PWORD DataGroup = (PWORD)((DWORD)RelocationDirectory + 8);

		//7��ѭ����ӡ���ݿ��е�����
		for (DWORD i = 0; i < DataNumber; i++)
		{
			//(1)�жϸ�4λ�Ƿ�Ϊ0
			if (DataGroup[i] >> 12 != 0)
			{
				//(2)��ȡ���ݿ��е���Ч���� ��12λ
				WORD BlockData = DataGroup[i] & 0xFFF;

				//(3)�������ݿ��RVA��FOA
				DWORD Data_RVA = RelocationDirectory->VirtualAddress + BlockData;
				DWORD Data_FOA = 0;
				ret = RVA_TO_FOA(FileAddress, Data_RVA, &Data_FOA);
				if (ret != 0)
				{
					printf("func RVA_TO_FOA() Error!\n");
					return ret;
				}

				//(4)��ȡ��Ҫ�ض�λ������
				PDWORD RelocationData = (PDWORD)((DWORD)FileAddress + Data_FOA);

				printf("��[%04X]��    |���� :[%04X]   |���ݵ�RVA :[%08X]  |�������� :[%X]  |�ض�λ����  :[%08X]\n", i+1, BlockData, Data_RVA, (DataGroup[i] >> 12), *RelocationData);
			}
		}
		
		printf("================= BlockData End ========================\n");
	
		//ָ����һ�����ݿ�
		RelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)RelocationDirectory + RelocationDirectory->SizeOfBlock);
	}


	return ret;
}


int main09()
{
	int ret = 0;
	PVOID FileAddress = NULL;

	//1�����ļ����뵽�ڴ�   
	ret = MyReadFile(&FileAddress);
	if (ret != 0)
	{
		if (FileAddress != NULL)
			free(FileAddress);
		return ret;
	}

	//2����ӡ�ض�λ����Ϣ
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





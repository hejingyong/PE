# define _CRT_SECURE_NO_WARNINGS
# include "stdio.h"
# include "stdlib.h"
# include "windows.h"
# include "PE.h"


/*
1����λ���������ӡ��������е����ݡ�ͬʱ��ӡ��INT���IAT��
*/

int PrintImportTable(PVOID FileAddress)
{
	int ret = 0;
	//1��ָ���������
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));

	//2����ȡ�����ĵ�ַ
	DWORD ImportDirectory_RVAAdd = pOptionalHeader->DataDirectory[1].VirtualAddress;
	DWORD ImportDirectory_FOAAdd = 0;
	//	(1)���жϵ�����Ƿ����
	if (ImportDirectory_RVAAdd == 0)
	{
		printf("ImportDirectory ������!\n");
		return ret;
	}
	//	(2)����ȡ������FOA��ַ
	ret = RVA_TO_FOA(FileAddress, ImportDirectory_RVAAdd, &ImportDirectory_FOAAdd);
	if (ret != 0)
	{
		printf("func RVA_TO_FOA() Error!\n");
		return ret;
	}

	//3��ָ�����
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)FileAddress + ImportDirectory_FOAAdd);

	//4��ѭ����ӡÿһ����������Ϣ  ��Ҫ��ԱΪ0ʱ����ѭ��
	while (ImportDirectory->FirstThunk && ImportDirectory->OriginalFirstThunk)
	{
		//	(1)��ȡ�����ļ�������
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
		
		//	(2)ָ��INT��
		DWORD OriginalFirstThunk_RVA = ImportDirectory->OriginalFirstThunk;
		DWORD OriginalFirstThunk_FOA = 0;
		ret = RVA_TO_FOA(FileAddress, OriginalFirstThunk_RVA, &OriginalFirstThunk_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}
		PDWORD OriginalFirstThunk_INT = (PDWORD)((DWORD)FileAddress + OriginalFirstThunk_FOA);
		
		//	(3)ѭ����ӡINT�������		������Ϊ0ʱ����
		while (*OriginalFirstThunk_INT)
		{
			//	(4)�����ж�,������λΪ1���ǰ���ŵ�����Ϣ,ȥ�����λ���Ǻ������,���������ֵ���
			if ((*OriginalFirstThunk_INT) >> 31)	//���λ��1,��ŵ���
			{
				//	(5)��ȡ�������
				DWORD Original = *OriginalFirstThunk_INT << 1 >> 1;	//ȥ����߱�־λ��
				printf("����ŵ���: %08Xh -- %08dd\n", Original, Original);	//16���� -- 10 ����
			}
			else	//���ֵ���
			{
				//	(5)��ȡ������
				DWORD ImportNameAdd_RAV = *OriginalFirstThunk_INT;
				DWORD ImportNameAdd_FOA = 0;
				ret = RVA_TO_FOA(FileAddress, ImportNameAdd_RAV, &ImportNameAdd_FOA);
				if (ret != 0)
				{
					printf("func RVA_TO_FOA() Error!\n");
					return ret;
				}
				PIMAGE_IMPORT_BY_NAME ImportName = (PIMAGE_IMPORT_BY_NAME)((DWORD)FileAddress + ImportNameAdd_FOA);
				printf("�����ֵ���[HINT/NAME]: %02X--%s\n", ImportName->Hint, ImportName->Name);
			}

			//	(6)ָ����һ����ַ
			OriginalFirstThunk_INT++;
		}
		printf("----------------------------------------------------------------\n");
		printf("FirstThunk RVA   :%08X\n", ImportDirectory->FirstThunk);
		printf("TimeDateStamp    :%08X\n", ImportDirectory->TimeDateStamp);

		//	(2)ָ��IAT��
		DWORD FirstThunk_RVA = ImportDirectory->FirstThunk;
		DWORD FirstThunk_FOA = 0;
		ret = RVA_TO_FOA(FileAddress, FirstThunk_RVA, &FirstThunk_FOA);
		if (ret != 0)
		{
			printf("func RVA_TO_FOA() Error!\n");
			return ret;
		}
		PDWORD FirstThunk_IAT = (PDWORD)((DWORD)FileAddress + FirstThunk_FOA);

		//	(3)�ж�IAT���Ƿ񱻰�	ʱ��� = 0:û�а󶨵�ַ	ʱ��� = 0xFFFFFFFF:�󶨵�ַ	����֪ʶ�ڰ󶨵������
		if (ImportDirectory->TimeDateStamp == 0xFFFFFFFF)
		{
			while (*FirstThunk_IAT)
			{
				printf("�󶨺�����ַ: %08X\n", *FirstThunk_IAT);
				FirstThunk_IAT++;
			}
		}
		else
		{
			//	(4)ѭ����ӡIAT�������		������Ϊ0ʱ����	��ӡ������INT��һ��
			while (*FirstThunk_IAT)
			{
				//	(5)�����ж�,������λΪ1���ǰ���ŵ�����Ϣ,ȥ�����λ���Ǻ������,���������ֵ���
				if ((*FirstThunk_IAT) >> 31)	//���λ��1,��ŵ���
				{
					//	(6)��ȡ�������
					DWORD Original = *FirstThunk_IAT << 1 >> 1;	//ȥ����߱�־λ��
					printf("����ŵ���: %08Xh -- %08dd\n", Original, Original);	//16���� -- 10 ����
				}
				else	//���ֵ���
				{
					//	(7)��ȡ������
					DWORD ImportNameAdd_RAV = *FirstThunk_IAT;
					DWORD ImportNameAdd_FOA = 0;
					ret = RVA_TO_FOA(FileAddress, ImportNameAdd_RAV, &ImportNameAdd_FOA);
					if (ret != 0)
					{
						printf("func RVA_TO_FOA() Error!\n");
						return ret;
					}
					PIMAGE_IMPORT_BY_NAME ImportName = (PIMAGE_IMPORT_BY_NAME)((DWORD)FileAddress + ImportNameAdd_FOA);
					printf("�����ֵ���[HINT/NAME]: %02X--%s\n", ImportName->Hint, ImportName->Name);
				}

				FirstThunk_IAT++;
			}

		}
		
		printf("=========================ImportTable %s End  =============================\n", pImportName);

		//	(8)ָ����һ�������
		ImportDirectory++;
	}

	return ret;
}

int main12()
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

	//2����ӡ�������Ϣ
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
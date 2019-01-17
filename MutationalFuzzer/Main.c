
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <windows.h>
#include <shlwapi.h>
#include <shlobj.h>

#include "Mutations.h"
#include "GeneralMutationDictionary.h"
#include "RmMutationDictionary.h"

#pragma comment(lib, "shlwapi.lib")

typedef struct
{
	LPVOID *base;
	DWORD size;

} __DLL_INFO;

typedef struct
{
	int threadId;
	char playerFilePath[MAX_PATH];
	char fileType[64];
	__MUTATION **mutationDictionaries;
	int mutationDictionariesCount;
	unsigned char *inputSampleData;
	int inputSampleSize;

} __FUZZING_THREAD_PARAMS;

DWORD processWaitTime;
HANDLE fuzzingThreads[256];

unsigned int GenerateRandomSeed();
void FuzzingThread(__FUZZING_THREAD_PARAMS *params);
float random_float(float min, float max);
void ExecuteMutation(__MUTATION *mutation, unsigned char *mutateLocation);
BOOL StartProcessForDebugging(char *processPath, char *inputFilePath);
void RandomFileName(char *fileName, int fileNameLength);

int main(int argc, char *argv[])
{
	char playerFilePath[MAX_PATH], inputFilePath[MAX_PATH], fileType[64];
	int numberOfFuzzingThreads, threadId;
	__MUTATION *specialMutationsDictionary;
	__FUZZING_THREAD_PARAMS *fuzzingThreadParams;
	unsigned char *inputSampleData;
	FILE *inputFile;
	int inputFileSize;

	if (argc < 5)
	{
		printf("Example usage: MutationalFuzzer.exe SoftPath InputFilePath ProcessWaitTimeInSeconds FileType ThreadsCount\n");
	}

	specialMutationsDictionary = NULL;

	memset(playerFilePath, 0x00, sizeof(playerFilePath));
	strcpy_s(playerFilePath, sizeof(playerFilePath), argv[1]);

	memset(inputFilePath, 0x00, sizeof(inputFilePath));
	strcpy_s(inputFilePath, sizeof(inputFilePath), argv[2]);

	processWaitTime = atoi(argv[3]);

	if (fopen_s(&inputFile, inputFilePath, "rb") != 0)
	{
		printf("Could not open input file\n");

		ExitProcess(0);
	}

	fseek(inputFile, 0, SEEK_END);
	inputFileSize = ftell(inputFile);
	fseek(inputFile, 0, SEEK_SET);
	inputSampleData = malloc(inputFileSize);
	fread(inputSampleData, sizeof(unsigned char), inputFileSize, inputFile);
	fclose(inputFile);

	memset(fileType, 0x00, sizeof(fileType));
	strcpy_s(fileType, sizeof(fileType), argv[4]);

	if (lstrcmpiA(fileType, "rm") == 0)
	{
		specialMutationsDictionary = RM_MUTATIONS;
	}
	else
	{
		MessageBoxA(NULL, "Invalid file type selected", NULL, MB_OK | MB_ICONERROR);

		ExitProcess(0);
	}

	numberOfFuzzingThreads = atoi(argv[5]);

	memset(fuzzingThreads, 0x00, sizeof(fuzzingThreads));

	for (threadId = 1; threadId <= numberOfFuzzingThreads; threadId++)
	{
		fuzzingThreadParams = malloc(sizeof(__FUZZING_THREAD_PARAMS));
		memset(fuzzingThreadParams, 0x00, sizeof(__FUZZING_THREAD_PARAMS));

		fuzzingThreadParams->threadId = threadId;
		strcpy_s(fuzzingThreadParams->playerFilePath, sizeof(fuzzingThreadParams->playerFilePath), playerFilePath);
		strcpy_s(fuzzingThreadParams->fileType, sizeof(fuzzingThreadParams->fileType), fileType);

		fuzzingThreadParams->mutationDictionaries = malloc(sizeof(__FUZZING_THREAD_PARAMS *));
		memset(fuzzingThreadParams->mutationDictionaries, 0x00, sizeof(__FUZZING_THREAD_PARAMS *));

		fuzzingThreadParams->inputSampleData = inputSampleData;
		fuzzingThreadParams->inputSampleSize = inputFileSize;

		fuzzingThreadParams->mutationDictionaries[0] = GENERAL_MUTATIONS;
		fuzzingThreadParams->mutationDictionaries[1] = specialMutationsDictionary;

		if (specialMutationsDictionary != NULL)
		{
			fuzzingThreadParams->mutationDictionariesCount = 2;
		}
		else
		{
			fuzzingThreadParams->mutationDictionariesCount = 1;
		}

		fuzzingThreads[threadId - 1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)FuzzingThread, fuzzingThreadParams, 0, NULL);
	}

	WaitForMultipleObjects(threadId - 1, fuzzingThreads, TRUE, INFINITE);

	return 0;
}

void FuzzingThread(__FUZZING_THREAD_PARAMS *params)
{
	char workDirectory[MAX_PATH], mutatedSamplePath[MAX_PATH];
	char crashedSamplePath[MAX_PATH], randomFileName[MAX_PATH];
	unsigned char *mutatedSampleData, *mutateLocation;
	int mutatedSampleIndex, mutationsCount;
	__MUTATION *mutationsDictionary, *selectedMutation;
	int mutatedSampleDataSize, mutateIndex, mutationsToExecute;
	HANDLE mutatedSampleFile;
	int fileChunksCount, renameError;
	DWORD bytesWritten;

	Sleep(params->threadId * 1000);

	srand(GenerateRandomSeed());

	memset(workDirectory, 0x00, sizeof(workDirectory));
	wsprintfA(workDirectory, "%d", params->threadId);

	CreateDirectoryA(workDirectory, NULL);

	mutatedSampleIndex = 1;

	mutatedSampleDataSize = params->inputSampleSize + 0x1000;
	mutatedSampleData = malloc(mutatedSampleDataSize); // 0x1000 to not worry about mutating last byte

	fileChunksCount = params->inputSampleSize / RAND_MAX;

	if (params->inputSampleSize % RAND_MAX > 0)
	{
		fileChunksCount++;
	}

	while (1)
	{
		// Select mutations count, select mutations dictionary, 
		// then select mutation from the dictionary, select mutations position and execute it on the data

		mutationsToExecute = (int)ceil((params->inputSampleSize * random_float((float)0.00, (float)0.05)) / 100.0);

		memset(mutatedSampleData, 0x00, mutatedSampleDataSize);
		memcpy(mutatedSampleData, params->inputSampleData, params->inputSampleSize);

		while (mutationsToExecute > 0)
		{
			mutationsDictionary = params->mutationDictionaries[rand() % params->mutationDictionariesCount];

			mutationsCount = 0;

			while (mutationsDictionary[mutationsCount].type != MUTATE_END)
			{
				mutationsCount++;
			}

			selectedMutation = &mutationsDictionary[rand() % mutationsCount];

			while (1)
			{
				mutateIndex = rand() % fileChunksCount;
				mutateIndex = (mutateIndex * RAND_MAX) + (rand() % RAND_MAX);

				if (mutateIndex > params->inputSampleSize - 1)
				{
					continue;
				}

				break;
			}

			mutateLocation = mutatedSampleData + mutateIndex;

			ExecuteMutation(selectedMutation, mutateLocation);

			mutationsToExecute--;
		}

		memset(mutatedSamplePath, 0x00, sizeof(mutatedSamplePath));
		wsprintfA(mutatedSamplePath, "%s\\mutated_sample_%d.%s", workDirectory, mutatedSampleIndex, params->fileType);

		remove(mutatedSamplePath);

		mutatedSampleFile = CreateFileA(mutatedSamplePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		bytesWritten = 0;
		WriteFile(mutatedSampleFile, mutatedSampleData, params->inputSampleSize, &bytesWritten, NULL);
		FlushFileBuffers(mutatedSampleFile);
		CloseHandle(mutatedSampleFile);

		if (StartProcessForDebugging(params->playerFilePath, mutatedSamplePath) == TRUE)
		{
			do
			{
				memset(randomFileName, 0x00, sizeof(randomFileName));
				RandomFileName(randomFileName, 36);

				memset(crashedSamplePath, 0x00, sizeof(crashedSamplePath));
				sprintf_s(crashedSamplePath, sizeof(crashedSamplePath), "%s\\%s.%s", workDirectory, randomFileName, params->fileType);

				renameError = rename(mutatedSamplePath, crashedSamplePath);

			} while (renameError != 0);

			printf(crashedSamplePath);
		}
		else
		{
			while (DeleteFileA(mutatedSamplePath) == FALSE)
			{
				Sleep(500);
			}
		}

		mutatedSampleIndex++;
	}
}

void ExecuteMutation(__MUTATION *mutation, unsigned char *mutateLocation)
{
	switch (mutation->type)
	{
	case MUTATE_OVERWRITE_BYTE:
	{
		*mutateLocation = mutation->byteValue;

		break;
	}

	case MUTATE_OVERWRITE_WORD:
	{
		*(WORD *)mutateLocation = mutation->wordValue;

		break;
	}

	case MUTATE_OVERWRITE_DWORD:
	{
		*(DWORD *)mutateLocation = mutation->dwordValue;

		break;
	}

	case MUTATE_OVERWRITE_BYTES:
	{
		memcpy(mutateLocation, mutation->bytesString, mutation->bytesStringLength);

		break;
	}

	case MUTATE_OVERWRITE_BYTE_WITH_RANDOM:
	{
		*mutateLocation = rand() % 256;

		break;
	}

	case MUTATE_OVERWRITE_WORD_WITH_RANDOM:
	{
		*(WORD *)mutateLocation = rand() % 65536;

		break;
	}

	case MUTATE_OVERWRITE_DWORD_WITH_RANDOM:
	{
		*(DWORD *)mutateLocation = rand() % 4294967296;

		break;
	}
	}
}

BOOL StartProcessForDebugging(char *processPath, char *inputFilePath)
{
	STARTUPINFOA startupInfo;
	PROCESS_INFORMATION processInfo;
	DEBUG_EVENT debugEvent;
	DWORD continueStatus;
	BOOL keepWaitingForDebugEvent, isDebugEventReceived;
	time_t startTime;
	char *commandLine, *filename;
	BOOL didCrashOccured;

	memset(&startupInfo, 0x00, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);
	memset(&processInfo, 0x00, sizeof(processInfo));

	commandLine = malloc(MAX_PATH);
	memset(commandLine, 0x00, MAX_PATH);
	filename = PathFindFileNameA(processPath);
	sprintf_s(commandLine, MAX_PATH, "%s \"%s\"", filename, inputFilePath);

	CreateProcessA(processPath, commandLine, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &startupInfo, &processInfo);

	free(commandLine);

	time(&startTime);

	keepWaitingForDebugEvent = TRUE;

	while (keepWaitingForDebugEvent)
	{
		continueStatus = DBG_CONTINUE;

		do
		{
			if (processWaitTime < difftime(time(0), startTime))
			{
				TerminateProcess(processInfo.hProcess, 0);
				TerminateThread(processInfo.hThread, 0);

				DebugActiveProcessStop(processInfo.dwProcessId);

				if (processInfo.hProcess != NULL)
				{
					CloseHandle(processInfo.hProcess);

					processInfo.hProcess = NULL;
				}

				if (processInfo.hThread != NULL)
				{
					CloseHandle(processInfo.hThread);

					processInfo.hThread = NULL;
				}


				return didCrashOccured;
			}

			memset(&debugEvent, 0x00, sizeof(debugEvent));
			isDebugEventReceived = WaitForDebugEvent(&debugEvent, 500);

		} while (isDebugEventReceived == FALSE || GetLastError() == ERROR_SEM_TIMEOUT);

		switch (debugEvent.dwDebugEventCode)
		{
		case 2:
		{
			break;
		}

		case 3:
		{
			CloseHandle(debugEvent.u.CreateProcessInfo.hFile);

			break;
		}

		case 6:
		{
			CloseHandle(debugEvent.u.LoadDll.hFile);

			break;
		}

		case EXCEPTION_DEBUG_EVENT:
		{
			switch (debugEvent.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_ACCESS_VIOLATION:
			case EXCEPTION_DATATYPE_MISALIGNMENT:
			case EXCEPTION_BREAKPOINT:
			case EXCEPTION_SINGLE_STEP:
			case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
			case EXCEPTION_FLT_DENORMAL_OPERAND:
			case EXCEPTION_FLT_DIVIDE_BY_ZERO:
			case EXCEPTION_FLT_INEXACT_RESULT:
			case EXCEPTION_FLT_INVALID_OPERATION:
			case EXCEPTION_FLT_OVERFLOW:
			case EXCEPTION_FLT_STACK_CHECK:
			case EXCEPTION_FLT_UNDERFLOW:
			case EXCEPTION_INT_DIVIDE_BY_ZERO:
			case EXCEPTION_INT_OVERFLOW:
			case EXCEPTION_PRIV_INSTRUCTION:
			case EXCEPTION_IN_PAGE_ERROR:
			case EXCEPTION_ILLEGAL_INSTRUCTION:
			case EXCEPTION_NONCONTINUABLE_EXCEPTION:
			case EXCEPTION_STACK_OVERFLOW:
			case EXCEPTION_INVALID_DISPOSITION:
			case EXCEPTION_GUARD_PAGE:
			case EXCEPTION_INVALID_HANDLE:
			{
				if (debugEvent.u.Exception.dwFirstChance == 0)
				{
					printf("Exception: %d - 0x%.8X\n", debugEvent.u.Exception.dwFirstChance, debugEvent.u.Exception.ExceptionRecord.ExceptionCode);
					printf("Exception Address: 0x%.8X\n", (DWORD)debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);

					didCrashOccured = TRUE;
					keepWaitingForDebugEvent = FALSE;
					
					TerminateProcess(processInfo.hProcess, 0);
					TerminateThread(processInfo.hThread, 0);

					DebugActiveProcessStop(processInfo.dwProcessId);
				}
				else
				{
					continueStatus = DBG_EXCEPTION_NOT_HANDLED;
				}

				break;
			}

			default:
			{
				break;
			}
			}

			break;
		}

		case EXIT_PROCESS_DEBUG_EVENT:
		{
			keepWaitingForDebugEvent = FALSE;

			break;
		}

		default:
		{
			break;
		}
		}

		ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus);
	}

	if (processInfo.hProcess != NULL)
	{
		CloseHandle(processInfo.hProcess);

		processInfo.hProcess = NULL;
	}

	if (processInfo.hThread != NULL)
	{
		CloseHandle(processInfo.hThread);

		processInfo.hThread = NULL;
	}

	return didCrashOccured;
}

unsigned int GenerateRandomSeed()
{
	LARGE_INTEGER performanceCounter;
	HCRYPTPROV hProvider;
	BYTE randomBlob[256];
	int randomSeedLength, i;
	unsigned int randomSeed;

	memset(&performanceCounter, 0x00, sizeof(performanceCounter));
	QueryPerformanceCounter(&performanceCounter);

	srand(performanceCounter.LowPart);

	CryptAcquireContextW(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
	randomSeedLength = rand() % sizeof(randomBlob);
	CryptGenRandom(hProvider, randomSeedLength, randomBlob);
	CryptReleaseContext(hProvider, 0);

	randomSeed = 0;

	for (i = 0; i < randomSeedLength; i++)
	{
		randomSeed += randomBlob[i];
	}

	return randomSeed;
}

float random_float(float min, float max)
{
	return min + (((float)rand()) / (float)RAND_MAX) * (max - min);
}

void RandomFileName(char *fileName, int fileNameLength)
{
	int i;

	for (i = 0; i < fileNameLength; i++)
	{
		fileName[i] = 'a' + (rand() % (('z' - 'a') + 1));
	}
}


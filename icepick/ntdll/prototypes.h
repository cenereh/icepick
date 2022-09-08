#pragma once
#include "nt.h"

typedef NTSTATUS(*f_NtOpenProcess)(PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES*, CLIENT_ID*);
typedef NTSTATUS(*f_NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSTATUS(*f_NtQueryInformationFile)(HANDLE hFile, PIO_STATUS_BLOCK io, PVOID InformationBuffer, ULONG InformationBufferLen, FILE_INFORMATION_CLASS fsi);
typedef NTSTATUS(*f_NtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(*f_NtClose)(HANDLE Handle);
typedef NTSTATUS(*f_NtReadFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE Routine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS(*f_NtWaitForSingleObject)(HANDLE Object, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
typedef NTSTATUS(*f_NtFreeVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
typedef NTSTATUS(*f_NtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PSIZE_T BytesToProtect, ULONG AccessProtection, PULONG OldProtection);
typedef NTSTATUS(*f_NtQueryPerformanceCounter)(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency);
typedef NTSTATUS(*f_NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(*f_NtQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
typedef NTSTATUS(*f_NtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS(*f_NtGetContextThread)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
typedef NTSTATUS(*f_NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
typedef NTSTATUS(*f_NtFlushInstructionCache)(HANDLE ProcessHandle, LPCVOID lpBaseAddress, SIZE_T Size);
typedef NTSTATUS(*f_NtSetContextThread)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
typedef NTSTATUS(*f_NtResumeThread)(HANDLE ThreadHandle, PULONG SuspendCount);
typedef NTSTATUS(*f_NtWriteFile)(HANDLE hFile, HANDLE hEvent, PIO_APC_ROUTINE IoApcRoutine, PVOID IoApcContext, PIO_STATUS_BLOCK pIoStatusBlock, PVOID WriteBuffer, ULONG WriteBufferLength, PLARGE_INTEGER FileOffset, PULONG LockOperationKey);

typedef NTSTATUS(*f_NtCreateProcess)	(	OUT PHANDLE 	ProcessHandle,
IN ACCESS_MASK 	DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes 	OPTIONAL,
IN HANDLE 	ParentProcess,
IN BOOL 	InheritObjectTable,
IN HANDLE SectionHandle 	OPTIONAL,
IN HANDLE DebugPort 	OPTIONAL,
IN HANDLE ExceptionPort 	OPTIONAL
);

typedef NTSTATUS(*f_NtCreateThread) (
  OUT PHANDLE             ThreadHandle,
  IN ACCESS_MASK          DesiredAccess,
  IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
  IN HANDLE               ProcessHandle,
  OUT PCLIENT_ID          ClientId,
  IN PCONTEXT             ThreadContext,
  IN PINITIAL_TEB         InitialTeb,
  IN BOOLEAN              CreateSuspended );
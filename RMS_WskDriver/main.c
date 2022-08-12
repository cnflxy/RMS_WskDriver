//#undef DBG
#include <ntddk.h>
#include <wsk.h>
#include "rms_user.h"

typedef struct _RMS_SEND_WORK_QUEUE {
	LIST_ENTRY Head;
	KSPIN_LOCK Lock;

	PIRP Irp;
	KEVENT CompletionEvent;
	KEVENT WakeEvent;
	PETHREAD Thread;
	NTSTATUS LastStatus;

	BOOLEAN Stop;
} RMS_SEND_WORK_QUEUE, * PRMS_SEND_WORK_QUEUE;

typedef struct _RMS_SEND_WORK_ENTRY {
	LIST_ENTRY Entry;

	_Field_size_bytes_(Length) PVOID Data;
	UINT64 Length;
} RMS_SEND_WORK_ENTRY, * PRMS_SEND_WORK_ENTRY;

typedef struct _RMS_DATA_BUFFER_QUEUE {
	LIST_ENTRY Head;
	KSPIN_LOCK Lock;

	NTSTATUS LastStatus;
	UINT64 TotalSize;
	//BOOLEAN Stop;
} RMS_DATA_BUFFER_QUEUE, * PRMS_DATA_BUFFER_QUEUE;

typedef struct _RMS_DATA_BUFFER_ENTRY {
	LIST_ENTRY Entry;

	_Field_size_bytes_part_(BufferSize, Length) PVOID DataBuffer;
	//UINT64 BufferSize;
	UINT64 Offset;
	UINT64 Length;
} RMS_DATA_BUFFER_ENTRY, * PRMS_DATA_BUFFER_ENTRY;

typedef struct _RMS_SOCKET {
	PWSK_SOCKET Wsk_Socket;
	PIRP Irp;
	KEVENT CompletionEvent;

	PRMS_SEND_WORK_QUEUE SendWorkQueue;
	PRMS_DATA_BUFFER_QUEUE ReceivedDataQueue;

	BOOLEAN Connected;
	//BOOLEAN Shutdown;
} RMS_SOCKET, * PRMS_SOCKET;

NTSTATUS
WSKAPI
RMS_WskReceiveEvent(
	_In_		PVOID SocketContext,
	_In_		ULONG Flags,
	_In_opt_	PWSK_DATA_INDICATION DataIndication,
	_In_        SIZE_T BytesIndicated,
	_Inout_     SIZE_T* BytesAccepted
);

NTSTATUS
WSKAPI
RMS_WskDisconnectEvent(
	_In_ PVOID SocketContext,
	_In_ ULONG Flags
);

static const
WSK_CLIENT_DISPATCH g_WskClientDispatch = {
  MAKE_WSK_VERSION(1,0),
  0,
  NULL
};

static const
WSK_CLIENT_CONNECTION_DISPATCH g_WskClientConnectionDispatch = {
	RMS_WskReceiveEvent,
	RMS_WskDisconnectEvent,
	NULL
};

static
WSK_REGISTRATION g_WskRegistration;

static
WSK_PROVIDER_NPI g_WskProviderNpi;

static
RMS_SOCKET g_RmsSocket;

static
RMS_SEND_WORK_QUEUE g_RmsSendWorkQueue;

static
RMS_DATA_BUFFER_QUEUE g_RmsReceivedDataQueue;

static
UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\RMS_WskDriver");
static
UNICODE_STRING g_Win32DeviceName = RTL_CONSTANT_STRING(L"\\DosDevices\\RMS_WskDriver");
static
PDEVICE_OBJECT g_DeviceObject;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD RMS_DriverUnload;
DRIVER_DISPATCH RMS_DriverCreate;
DRIVER_DISPATCH RMS_DriverClose;
DRIVER_DISPATCH RMS_DriverIoControl;
KSTART_ROUTINE RMS_SendWorkerThread;

NTSTATUS
RMS_AllocateSocket(
	_In_ PRMS_SOCKET Socket,
	_In_ PRMS_SEND_WORK_QUEUE SendWorkQueue,
	_In_ PRMS_DATA_BUFFER_QUEUE ReceivedDataQueue
);

VOID
RMS_ReleaseSocket(
	_In_ PRMS_SOCKET Socket
);

//NTSTATUS
//RMS_StartSendWorker(
//	PRMS_SOCKET Socket
//);

NTSTATUS
RMS_Connect(
	_In_ PRMS_SOCKET Socket,
	_In_ PSOCKADDR RemoteAddress
);

NTSTATUS
RMS_Disconnect(
	_In_ PRMS_SOCKET Socket
);

NTSTATUS
RMS_Close(
	_In_ PRMS_SOCKET Socket
);

NTSTATUS
RMS_Send(
	_In_ PRMS_SOCKET Socket,
	_In_ PVOID Data,
	_In_ UINT64 Length,
	_Out_ PUINT64 SentLength
);

NTSTATUS
RMS_EnSendWorkQueue(
	_In_ PRMS_SEND_WORK_QUEUE Queue,
	_In_ PVOID Data,
	_In_ UINT64 Length
);

NTSTATUS
RMS_EnReceivedDataQueue(
	_In_ PRMS_DATA_BUFFER_QUEUE Queue,
	_In_ PWSK_DATA_INDICATION Data,
	_In_ UINT64 Length
);

VOID
RMS_ClearReceivedDataQueue(
	_In_ PRMS_DATA_BUFFER_QUEUE Queue
);

NTSTATUS
RMS_WskIoCompletionRoutine(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp,
	_Inout_ PVOID Context
);

USHORT
Wsk_HTONS(
	_In_ USHORT hs
);

USHORT
Wsk_NTOHS(
	_In_ USHORT ns
);

#ifdef ALLOC_PRAGMA

#pragma alloc_text(INIT, DriverEntry)
//#pragma alloc_text(PAGE, RMS_StartSendWorker)
#pragma alloc_text(PAGE, RMS_DriverUnload)
#pragma alloc_text(PAGE, RMS_DriverCreate)
#pragma alloc_text(PAGE, RMS_DriverClose)
#pragma alloc_text(PAGE, RMS_DriverIoControl)
#pragma alloc_text(PAGE, RMS_SendWorkerThread)
#pragma alloc_text(PAGE, RMS_AllocateSocket)
#pragma alloc_text(PAGE, RMS_ReleaseSocket)
#pragma alloc_text(PAGE, RMS_Connect)
#pragma alloc_text(PAGE, RMS_Disconnect)
#pragma alloc_text(PAGE, RMS_Close)
#pragma alloc_text(PAGE, RMS_Send)
#pragma alloc_text(PAGE, RMS_EnSendWorkQueue)
#pragma alloc_text(PAGE, RMS_ClearReceivedDataQueue)
#pragma alloc_text(PAGE, Wsk_HTONS)
#pragma alloc_text(PAGE, Wsk_NTOHS)

#endif

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	NTSTATUS ntStatus;
	//RtlNtStatusToDosError()

	UNREFERENCED_PARAMETER(RegistryPath);
	PAGED_CODE();

	//KdBreakPoint();

	ntStatus = IoCreateDevice(
		DriverObject,
		0,
		&g_DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		TRUE,
		&g_DeviceObject
	);
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CreateDevice failed: %x\n", ntStatus);
		return ntStatus;
	}

	ntStatus = IoCreateSymbolicLink(&g_Win32DeviceName, &g_DeviceName);
	if (!NT_SUCCESS(ntStatus)) {
		IoDeleteDevice(g_DeviceObject);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CreateSymbolicLink failed: %x\n", ntStatus);
		return ntStatus;
	}

	DriverObject->DriverUnload = RMS_DriverUnload;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = RMS_DriverCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = RMS_DriverClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RMS_DriverIoControl;

	//g_DeviceObject->Flags |= DO_DIRECT_IO;
	//g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}

VOID
RMS_DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	//KdBreakPoint();
	IoDeleteSymbolicLink(&g_Win32DeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS
RMS_DriverCreate(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	NTSTATUS ntStatus;
	WSK_CLIENT_NPI wskClientNpi;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	//KdBreakPoint();

	wskClientNpi.ClientContext = NULL;
	wskClientNpi.Dispatch = &g_WskClientDispatch;
	ntStatus = WskRegister(&wskClientNpi, &g_WskRegistration);
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WskRegister failed: %x\n", ntStatus);
		goto Done;
	}

	ntStatus = WskCaptureProviderNPI(&g_WskRegistration, WSK_INFINITE_WAIT, &g_WskProviderNpi);
	if (!NT_SUCCESS(ntStatus)) {
		WskDeregister(&g_WskRegistration);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WskCaptureProviderNPI failed: %x\n", ntStatus);
		goto Done;
	}

	ntStatus = RMS_AllocateSocket(&g_RmsSocket, &g_RmsSendWorkQueue, &g_RmsReceivedDataQueue);
	if (!NT_SUCCESS(ntStatus)) {
		WskReleaseProviderNPI(&g_WskRegistration);
		WskDeregister(&g_WskRegistration);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "AllocateSocket failed: %x\n", ntStatus);
		goto Done;
	}

Done:
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = ntStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntStatus;
}

NTSTATUS
RMS_DriverClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	NTSTATUS ntStatus;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	//KdBreakPoint();

	RMS_ReleaseSocket(&g_RmsSocket);

	WskReleaseProviderNPI(&g_WskRegistration);
	WskDeregister(&g_WskRegistration);

	ntStatus = STATUS_SUCCESS;

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = ntStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntStatus;
}

NTSTATUS
RMS_DriverIoControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	NTSTATUS ntStatus;
	PIO_STACK_LOCATION irpStackPtr;
	UINT64 outLength = 0;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	//KdBreakPoint();

	irpStackPtr = IoGetCurrentIrpStackLocation(Irp);

	switch (irpStackPtr->Parameters.DeviceIoControl.IoControlCode) {
	case RMS_IOCTL_CONNECT:
		if (irpStackPtr->Parameters.DeviceIoControl.InputBufferLength != sizeof(SOCKADDR_IN)) {
			ntStatus = STATUS_INVALID_PARAMETER_1;
			break;
		}
		if (irpStackPtr->Parameters.DeviceIoControl.OutputBufferLength) {
			ntStatus = STATUS_INVALID_PARAMETER_2;
			break;
		}

		if (g_RmsSocket.Connected) {
			ntStatus = STATUS_CONNECTION_ACTIVE;
			break;
		}

		PSOCKADDR_IN remoteAddress = Irp->AssociatedIrp.SystemBuffer;
		DbgPrintEx(
			DPFLTR_IHVDRIVER_ID,
			DPFLTR_ERROR_LEVEL,
			"connect to %d.%d.%d.%d:%d\n",
			remoteAddress->sin_addr.s_net,
			remoteAddress->sin_addr.s_host,
			remoteAddress->sin_addr.s_lh,
			remoteAddress->sin_addr.s_impno,
			Wsk_NTOHS(remoteAddress->sin_port)
		);

		ntStatus = RMS_Connect(&g_RmsSocket, (PSOCKADDR)remoteAddress);
		break;

	case RMS_IOCTL_DISCONNECT:
		if (irpStackPtr->Parameters.DeviceIoControl.InputBufferLength) {
			ntStatus = STATUS_INVALID_PARAMETER_1;
			break;
		}
		if (irpStackPtr->Parameters.DeviceIoControl.OutputBufferLength) {
			ntStatus = STATUS_INVALID_PARAMETER_2;
			break;
		}

		if (!g_RmsSocket.Connected) {
			ntStatus = STATUS_CONNECTION_INVALID;
			break;
		}

		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "disconnecting\n");

		ntStatus = RMS_Disconnect(&g_RmsSocket);
		break;

	case RMS_IOCTL_SEND:
		if (irpStackPtr->Parameters.DeviceIoControl.InputBufferLength) {
			ntStatus = STATUS_INVALID_PARAMETER_1;
			break;
		}
		if (!irpStackPtr->Parameters.DeviceIoControl.OutputBufferLength) {
			ntStatus = STATUS_INVALID_PARAMETER_2;
			break;
		}

		if (!g_RmsSocket.Connected) {
			ntStatus = STATUS_CONNECTION_INVALID;
			break;
		}

		if (!NT_SUCCESS(g_RmsSendWorkQueue.LastStatus)) {
			ntStatus = g_RmsSendWorkQueue.LastStatus;
			break;
		}

		UINT64 sendDataLength = irpStackPtr->Parameters.DeviceIoControl.OutputBufferLength;
		PVOID sendData = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, LowPagePriority | MdlMappingNoExecute);
		if (!sendData) {
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		//KdBreakPoint();

		ntStatus = RMS_EnSendWorkQueue(&g_RmsSendWorkQueue, sendData, sendDataLength);
		if (NT_SUCCESS(ntStatus)) {
			outLength = sendDataLength;
		}
		break;

	case RMS_IOCTL_RECV:
		if (irpStackPtr->Parameters.DeviceIoControl.InputBufferLength) {
			ntStatus = STATUS_INVALID_PARAMETER_1;
			break;
		}
		if (!irpStackPtr->Parameters.DeviceIoControl.OutputBufferLength) {
			ntStatus = STATUS_INVALID_PARAMETER_2;
			break;
		}

		if (!g_RmsReceivedDataQueue.TotalSize) {
			ntStatus = STATUS_SUCCESS;
			break;
		}

		UINT64 recvBufferLength = irpStackPtr->Parameters.DeviceIoControl.OutputBufferLength;
		PVOID recvBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, LowPagePriority | MdlMappingNoExecute);
		if (!recvBuffer) {
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		//KdBreakPoint();

		KIRQL oldIrql;
		UINT64 recvBufferOffset = 0, copySize;
		PLIST_ENTRY listEntry;
		while (!IsListEmpty(&g_RmsReceivedDataQueue.Head)) {
			KeAcquireSpinLock(&g_RmsReceivedDataQueue.Lock, &oldIrql);
			//if (!IsListEmpty(&g_RmsReceivedDataQueue.Head)) {
			listEntry = RemoveHeadList(&g_RmsReceivedDataQueue.Head);
			//} else {
				//listEntry = NULL;
			//}
			KeReleaseSpinLock(&g_RmsReceivedDataQueue.Lock, oldIrql);

			//if (!listEntry) break;

			PRMS_DATA_BUFFER_ENTRY dataBufferEntry = CONTAINING_RECORD(listEntry, RMS_DATA_BUFFER_ENTRY, Entry);
			if (dataBufferEntry->Length - dataBufferEntry->Offset >= recvBufferLength - recvBufferOffset) {
				copySize = recvBufferLength - recvBufferOffset;
			} else {
				copySize = dataBufferEntry->Length - dataBufferEntry->Offset;
			}
			RtlCopyMemory((PUCHAR)recvBuffer + recvBufferOffset, (PUCHAR)dataBufferEntry->DataBuffer + dataBufferEntry->Offset, (SIZE_T)copySize);
			recvBufferOffset += copySize;
			dataBufferEntry->Offset += copySize;

			if (dataBufferEntry->Offset == dataBufferEntry->Length) {
				ExFreePool(dataBufferEntry->DataBuffer);
				ExFreePool(dataBufferEntry);
				dataBufferEntry = NULL;
			}

			if (recvBufferOffset == recvBufferLength) {
				if (dataBufferEntry) {
					KeAcquireSpinLock(&g_RmsReceivedDataQueue.Lock, &oldIrql);
					InsertHeadList(&g_RmsReceivedDataQueue.Head, &dataBufferEntry->Entry);
					KeReleaseSpinLock(&g_RmsReceivedDataQueue.Lock, oldIrql);
				}
				break;
			}
		}

		KeAcquireSpinLock(&g_RmsReceivedDataQueue.Lock, &oldIrql);
		g_RmsReceivedDataQueue.TotalSize -= recvBufferOffset;
		KeReleaseSpinLock(&g_RmsReceivedDataQueue.Lock, oldIrql);

		/*KeAcquireSpinLock(&g_RmsReceivedDataQueue.Lock, &oldIrql);
		PLIST_ENTRY listEntry = RemoveHeadList(&g_RmsReceivedDataQueue.Head);
		while (listEntry != &g_RmsReceivedDataQueue.Head) {
			PRMS_DATA_BUFFER_ENTRY dataBufferEntry = CONTAINING_RECORD(listEntry, RMS_DATA_BUFFER_ENTRY, Entry);
			if (dataBufferEntry->Length - dataBufferEntry->Offset >= recvBufferLength - recvBufferOffset) {
				copySize = recvBufferLength - recvBufferOffset;
			} else {
				copySize = dataBufferEntry->Length - dataBufferEntry->Offset;
			}
			RtlCopyMemory((PUCHAR)recvBuffer + recvBufferOffset, (PUCHAR)dataBufferEntry->DataBuffer + dataBufferEntry->Offset, (SIZE_T)copySize);
			recvBufferOffset += copySize;
			dataBufferEntry->Offset += copySize;

			if (dataBufferEntry->Offset == dataBufferEntry->Length) {
				ExFreePool(dataBufferEntry->DataBuffer);
				ExFreePool(dataBufferEntry);
				dataBufferEntry = NULL;
			}

			if (recvBufferOffset == recvBufferLength) {
				if (dataBufferEntry && dataBufferEntry->Offset != dataBufferEntry->Length) {
					InsertHeadList(&g_RmsReceivedDataQueue.Head, &dataBufferEntry->Entry);
				}
				break;
			}

			if (!dataBufferEntry) {
				listEntry = RemoveHeadList(&g_RmsReceivedDataQueue.Head);
			}
		}

		g_RmsReceivedDataQueue.TotalSize -= recvBufferOffset;
		KeReleaseSpinLock(&g_RmsReceivedDataQueue.Lock, oldIrql);*/

		if (!recvBufferOffset && !NT_SUCCESS(g_RmsReceivedDataQueue.LastStatus)) {
			ntStatus = g_RmsReceivedDataQueue.LastStatus;
			break;
		}

		outLength = recvBufferOffset;
		ntStatus = STATUS_SUCCESS;
		break;

	case RMS_IOCTL_CONNECTED:
		if (irpStackPtr->Parameters.DeviceIoControl.InputBufferLength) {
			ntStatus = STATUS_INVALID_PARAMETER_1;
			break;
		}
		if (irpStackPtr->Parameters.DeviceIoControl.OutputBufferLength) {
			ntStatus = STATUS_INVALID_PARAMETER_2;
			break;
		}

		if (g_RmsSocket.Connected) {
			ntStatus = STATUS_SUCCESS;
		} else {
			ntStatus = STATUS_CONNECTION_INVALID;
		}

		break;

	case RMS_IOCTL_RECEIVED:
		if (irpStackPtr->Parameters.DeviceIoControl.InputBufferLength) {
			ntStatus = STATUS_INVALID_PARAMETER_1;
			break;
		}
		if (irpStackPtr->Parameters.DeviceIoControl.OutputBufferLength != sizeof(UINT64)) {
			ntStatus = STATUS_INVALID_PARAMETER_2;
			break;
		}

		if (!g_RmsSocket.Connected) {
			ntStatus = STATUS_CONNECTION_INVALID;
			break;
		}

		PUINT64 recvivedBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, LowPagePriority | MdlMappingNoExecute);
		if (!recvivedBuffer) {
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		*recvivedBuffer = g_RmsReceivedDataQueue.TotalSize;
		outLength = sizeof(UINT64);
		ntStatus = STATUS_SUCCESS;
		break;

	default:
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"unknown ioctl code: 0x%x\n",
			irpStackPtr->Parameters.DeviceIoControl.IoControlCode
		);
		ntStatus = STATUS_INVALID_DEVICE_REQUEST;
	}

	Irp->IoStatus.Information = (SIZE_T)outLength;
	Irp->IoStatus.Status = ntStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntStatus;
}

VOID
RMS_SendWorkerThread(
	_In_ PVOID StartContext
)
{
	NTSTATUS ntStatus;
	PRMS_SOCKET Socket;
	PRMS_SEND_WORK_QUEUE Queue;
	PLIST_ENTRY listEntry;

	PAGED_CODE();

	//KdBreakPoint();

	Socket = StartContext;
	Queue = Socket->SendWorkQueue;

	for (;;) {
		listEntry = ExInterlockedRemoveHeadList(&Queue->Head, &Queue->Lock);

		if (listEntry == NULL) {
			//KdBreakPoint();

			if (Queue->Stop) {
				break;
			}

			KeWaitForSingleObject(
				&Queue->WakeEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL
			);

			continue;
		}

		//KdBreakPoint();

		PRMS_SEND_WORK_ENTRY sendWorkEntry = CONTAINING_RECORD(listEntry, RMS_SEND_WORK_ENTRY, Entry);

		if (Socket->Connected && !Queue->Stop) {
			UINT64 sentLength;
			ntStatus = RMS_Send(Socket, sendWorkEntry->Data, sendWorkEntry->Length, &sentLength);
			if (!NT_SUCCESS(ntStatus)) {
				if (!sentLength) {
					Socket->Connected = FALSE;
				} else {
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Send partial data %llu/%llu: %x\n", sentLength, sendWorkEntry->Length, ntStatus);
				}
				//Socket->Connected = TRUE;
			}
		} else {
			ntStatus = STATUS_CONNECTION_INVALID;
		}

		Queue->LastStatus = ntStatus;

		ExFreePool(sendWorkEntry->Data);
		ExFreePool(sendWorkEntry);
	}

	//KdBreakPoint();

	PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
RMS_AllocateSocket(
	_In_ PRMS_SOCKET Socket,
	_In_ PRMS_SEND_WORK_QUEUE SendWorkQueue,
	_In_ PRMS_DATA_BUFFER_QUEUE ReceivedDataQueue
)
{
	NTSTATUS ntStatus;
	HANDLE hThread;

	PAGED_CODE();

	Socket->Irp = IoAllocateIrp(1, FALSE);
	if (!Socket->Irp) {
		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Allocate ControlIrp failed: %x\n", ntStatus);
		goto Done;
	}

	SendWorkQueue->Irp = IoAllocateIrp(1, FALSE);
	if (!SendWorkQueue->Irp) {
		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Allocate SendIrp failed: %x\n", ntStatus);
		goto Done;
	}

	InitializeListHead(&SendWorkQueue->Head);
	KeInitializeSpinLock(&SendWorkQueue->Lock);
	KeInitializeEvent(&SendWorkQueue->WakeEvent, SynchronizationEvent, FALSE);
	KeInitializeEvent(&SendWorkQueue->CompletionEvent, SynchronizationEvent, FALSE);
	InitializeListHead(&ReceivedDataQueue->Head);
	KeInitializeSpinLock(&ReceivedDataQueue->Lock);
	KeInitializeEvent(&Socket->CompletionEvent, SynchronizationEvent, FALSE);
	SendWorkQueue->Stop = FALSE;
	SendWorkQueue->LastStatus = STATUS_SUCCESS;
	//ReceivedDataQueue->Stop = FALSE;
	ReceivedDataQueue->LastStatus = STATUS_SUCCESS;
	Socket->Connected = FALSE;
	Socket->SendWorkQueue = SendWorkQueue;
	Socket->ReceivedDataQueue = ReceivedDataQueue;

	ntStatus = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, RMS_SendWorkerThread, Socket);
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Create SendWorkerThread failed: %x\n", ntStatus);
		goto Done;
	}

	ntStatus = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &SendWorkQueue->Thread, NULL);

	ZwClose(hThread);

	if (!NT_SUCCESS(ntStatus)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Reference SendWorkerThread Object failed: %x\n", ntStatus);
		SendWorkQueue->Stop = TRUE;
		KeSetEvent(&SendWorkQueue->WakeEvent, IO_NO_INCREMENT, FALSE);
		goto Done;
	}

	ntStatus = STATUS_SUCCESS;

Done:
	if (!NT_SUCCESS(ntStatus)) {
		if (Socket->Irp) {
			IoFreeIrp(Socket->Irp);
			Socket->Irp = NULL;
		}

		if (SendWorkQueue->Irp) {
			IoFreeIrp(SendWorkQueue->Irp);
			SendWorkQueue->Irp = NULL;
		}

		//RtlSecureZeroMemory(SendWorkQueue, sizeof(*SendWorkQueue));
		//RtlSecureZeroMemory(ReceiveDataQueue, sizeof(*ReceiveDataQueue));
		//RtlSecureZeroMemory(Socket, sizeof(*Socket));
	}

	return ntStatus;
}

VOID
RMS_ReleaseSocket(
	_In_ PRMS_SOCKET Socket
)
{
	PAGED_CODE();

	//if (Socket->Shutdown) {
	//	return STATUS_SUCCESS;
	//}

	Socket->SendWorkQueue->Stop = TRUE;
	KeSetEvent(&Socket->SendWorkQueue->WakeEvent, IO_NO_INCREMENT, FALSE);
	KeWaitForSingleObject(Socket->SendWorkQueue->Thread, Executive, KernelMode, FALSE, NULL);
	ObDereferenceObject(Socket->SendWorkQueue->Thread);

	//KdBreakPoint();

	//Socket->ReceivedDataQueue->Stop = TRUE;

	RMS_Disconnect(Socket);
	RMS_Close(Socket);

	//if (Socket->Wsk_Socket) {
	//	if (Socket->Connected) {
	//		RMS_Disconnect(Socket);
	//	}
	//	RMS_Close(Socket);
	//	//Socket->Wsk_Socket = NULL;
	//}

	//if (Socket->Irp) {
	IoFreeIrp(Socket->Irp);
	Socket->Irp = NULL;
	//}

	//if (Socket->SendWorkQueue->Irp) {
	IoFreeIrp(Socket->SendWorkQueue->Irp);
	Socket->SendWorkQueue->Irp = NULL;
	//}

	//	RtlSecureZeroMemory(Socket->SendWorkQueue, sizeof(*Socket->SendWorkQueue));
	//RtlSecureZeroMemory(Socket, sizeof(*Socket));
}

NTSTATUS
RMS_Connect(
	_In_ PRMS_SOCKET Socket,
	_In_ PSOCKADDR RemoteAddress
)
{
	NTSTATUS ntStatus;
	SOCKADDR_IN localAddress;
	const WSK_PROVIDER_BASIC_DISPATCH* basicDispatch;
	WSK_EVENT_CALLBACK_CONTROL eventCallbackControl;

	PAGED_CODE();

	if (g_RmsSocket.Connected) {
		return STATUS_CONNECTION_ACTIVE;
	}

	if (RemoteAddress->sa_family != AF_INET) {
		return STATUS_INVALID_PARAMETER_2;
	}

	if (Socket->Wsk_Socket) {
		RMS_Close(Socket);
	}

	IoReuseIrp(Socket->Irp, STATUS_UNSUCCESSFUL);

	IoSetCompletionRoutine(
		Socket->Irp,
		RMS_WskIoCompletionRoutine,
		&Socket->CompletionEvent,
		TRUE,
		TRUE,
		TRUE
	);

	RtlSecureZeroMemory(&localAddress, sizeof(localAddress));
	localAddress.sin_family = AF_INET;
	localAddress.sin_addr.s_addr = IN4ADDR_ANY;
	localAddress.sin_port = 0;

	ntStatus = g_WskProviderNpi.Dispatch->WskSocketConnect(
		g_WskProviderNpi.Client,
		SOCK_STREAM,
		IPPROTO_TCP,
		(PSOCKADDR)&localAddress,
		RemoteAddress,
		0,
		Socket,
		&g_WskClientConnectionDispatch,
		NULL,
		NULL,
		NULL,
		Socket->Irp
	);

	KeWaitForSingleObject(&Socket->CompletionEvent, Executive, KernelMode, FALSE, NULL);
	ntStatus = Socket->Irp->IoStatus.Status;

	if (NT_SUCCESS(ntStatus)) {
		Socket->Wsk_Socket = (PWSK_SOCKET)Socket->Irp->IoStatus.Information;

		IoReuseIrp(Socket->Irp, STATUS_UNSUCCESSFUL);

		IoSetCompletionRoutine(
			Socket->Irp,
			RMS_WskIoCompletionRoutine,
			&Socket->CompletionEvent,
			TRUE,
			TRUE,
			TRUE
		);

		basicDispatch = Socket->Wsk_Socket->Dispatch;

		eventCallbackControl.NpiId = &NPI_WSK_INTERFACE_ID;
		eventCallbackControl.EventMask = WSK_EVENT_RECEIVE | WSK_EVENT_DISCONNECT;

		ntStatus = basicDispatch->WskControlSocket(
			Socket->Wsk_Socket,
			WskSetOption,
			SO_WSK_EVENT_CALLBACK,
			SOL_SOCKET,
			sizeof(WSK_EVENT_CALLBACK_CONTROL),
			&eventCallbackControl,
			0,
			NULL,
			NULL,
			Socket->Irp
		);

		KeWaitForSingleObject(&Socket->CompletionEvent, Executive, KernelMode, FALSE, NULL);
		ntStatus = Socket->Irp->IoStatus.Status;

		if (!NT_SUCCESS(ntStatus)) {
			RMS_Disconnect(Socket);
			RMS_Close(Socket);
			Socket->Wsk_Socket = NULL;
		} else {
			Socket->Connected = TRUE;
		}
	}

	return ntStatus;
}

NTSTATUS
RMS_Disconnect(
	_In_ PRMS_SOCKET Socket
)
{
	NTSTATUS ntStatus;
	PWSK_PROVIDER_CONNECTION_DISPATCH connectionDispatch;

	PAGED_CODE();

	if (!Socket->Connected) {
		return STATUS_CONNECTION_INVALID;
	}

	IoReuseIrp(Socket->Irp, STATUS_UNSUCCESSFUL);

	IoSetCompletionRoutine(
		Socket->Irp,
		RMS_WskIoCompletionRoutine,
		&Socket->CompletionEvent,
		TRUE,
		TRUE,
		TRUE
	);

	connectionDispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Wsk_Socket->Dispatch;

	ntStatus = connectionDispatch->WskDisconnect(
		Socket->Wsk_Socket,
		NULL,
		0,  // WSK_FLAG_ABORTIVE
		Socket->Irp
	);

	KeWaitForSingleObject(&Socket->CompletionEvent, Executive, KernelMode, FALSE, NULL);
	ntStatus = Socket->Irp->IoStatus.Status;

	Socket->Connected = FALSE;
	RMS_ClearReceivedDataQueue(Socket->ReceivedDataQueue);

	return ntStatus;
}

NTSTATUS
RMS_Close(
	_In_ PRMS_SOCKET Socket
)
{
	NTSTATUS Status;
	PWSK_PROVIDER_BASIC_DISPATCH WskProviderBasicDispatch;

	PAGED_CODE();

	if (!Socket->Wsk_Socket) {
		return STATUS_SUCCESS;
	}

	if (Socket->Connected) {
		RMS_Disconnect(Socket);
	}

	IoReuseIrp(Socket->Irp, STATUS_UNSUCCESSFUL);

	IoSetCompletionRoutine(
		Socket->Irp,
		RMS_WskIoCompletionRoutine,
		&Socket->CompletionEvent,
		TRUE,
		TRUE,
		TRUE
	);

	WskProviderBasicDispatch = (PWSK_PROVIDER_BASIC_DISPATCH)Socket->Wsk_Socket->Dispatch;
	Status = WskProviderBasicDispatch->WskCloseSocket(Socket->Wsk_Socket, Socket->Irp);

	KeWaitForSingleObject(&Socket->CompletionEvent, Executive, KernelMode, FALSE, NULL);
	Status = Socket->Irp->IoStatus.Status;

	Socket->Wsk_Socket = NULL;

	//Socket->ReceivedDataQueue->Stop = TRUE;
	RMS_ClearReceivedDataQueue(Socket->ReceivedDataQueue);

	return Status;
}

NTSTATUS
RMS_Send(
	_In_ PRMS_SOCKET Socket,
	_In_ PVOID Data,
	_In_ UINT64 Length,
	_Out_ PUINT64 SentLength
)
{
	PRMS_SEND_WORK_QUEUE Queue;
	WSK_BUF wskBuf;
	PWSK_PROVIDER_CONNECTION_DISPATCH connectionDispatch;
	NTSTATUS ntStatus;

	PAGED_CODE();

	if (!Socket->Wsk_Socket || !Socket->Connected) {
		return STATUS_CONNECTION_INVALID;
	}

	wskBuf.Mdl = IoAllocateMdl(Data, (ULONG)Length, FALSE, FALSE, NULL);
	if (!wskBuf.Mdl) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	wskBuf.Offset = 0;
	wskBuf.Length = (SIZE_T)Length;

	//MmProbeAndLockPages(WskSendBuf.Mdl, KernelMode, IoReadAccess);

	MmBuildMdlForNonPagedPool(wskBuf.Mdl);

	Queue = Socket->SendWorkQueue;

	IoReuseIrp(Queue->Irp, STATUS_UNSUCCESSFUL);

	IoSetCompletionRoutine(
		Queue->Irp,
		RMS_WskIoCompletionRoutine,
		&Queue->CompletionEvent,
		TRUE,
		TRUE,
		TRUE
	);

	connectionDispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Wsk_Socket->Dispatch;

	ntStatus = connectionDispatch->WskSend(
		Socket->Wsk_Socket,
		&wskBuf,
		0,
		Queue->Irp
	);

	KeWaitForSingleObject(&Queue->CompletionEvent, Executive, KernelMode, FALSE, NULL);
	ntStatus = Queue->Irp->IoStatus.Status;
	//KdBreakPoint();

	if (NT_SUCCESS(ntStatus)) {
		*SentLength = Queue->Irp->IoStatus.Information;
	} else {
		*SentLength = 0;
	}

	IoFreeMdl(wskBuf.Mdl);

	return ntStatus;
}

NTSTATUS
RMS_EnSendWorkQueue(
	_In_ PRMS_SEND_WORK_QUEUE Queue,
	_In_ PVOID Data,
	_In_ UINT64 Length
)
{
	PAGED_CODE();

	if (Queue->Stop) {
		return STATUS_CONNECTION_INVALID;
	}

	PRMS_SEND_WORK_ENTRY newEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(RMS_SEND_WORK_ENTRY), 'EsmR');
	if (!newEntry) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlSecureZeroMemory(newEntry, sizeof(RMS_SEND_WORK_ENTRY));

	newEntry->Data = ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)Length, 'DsmR');
	if (!newEntry->Data) {
		ExFreePool(newEntry);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	newEntry->Length = Length;
	RtlCopyMemory(newEntry->Data, Data, (SIZE_T)Length);

	if (!ExInterlockedInsertTailList(&Queue->Head, &newEntry->Entry, &Queue->Lock)) {
		KeSetEvent(&Queue->WakeEvent, IO_NO_INCREMENT, FALSE);
	}

	return STATUS_SUCCESS;
}

NTSTATUS
RMS_EnReceivedDataQueue(
	_In_ PRMS_DATA_BUFFER_QUEUE Queue,
	_In_ PWSK_DATA_INDICATION Data,
	_In_ UINT64 Length
)
{
	//PAGED_CODE();

	//if (Queue->Stop) {
		//return STATUS_CONNECTION_ABORTED;
	//}

	//KIRQL oldIrql;
	//KeAcquireSpinLock(&Queue->Lock, &oldIrql);


	PRMS_DATA_BUFFER_ENTRY newEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(RMS_DATA_BUFFER_ENTRY), 'EsmR');
	if (!newEntry) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlSecureZeroMemory(newEntry, sizeof(RMS_DATA_BUFFER_ENTRY));

	newEntry->DataBuffer = ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)Length, 'DsmR');
	if (!newEntry->DataBuffer) {
		ExFreePool(newEntry);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	newEntry->Length = Length;

	PWSK_DATA_INDICATION dataPtr = Data;
	SIZE_T copyOffset = 0;
	while (dataPtr) {
		//PVOID pVa = MmGetSystemAddressForMdlSafe(dataPtr->Buffer.Mdl, LowPagePriority | MdlMappingNoExecute);
		//PVOID pRealVa = (PUCHAR)pVa + MmGetMdlByteOffset(dataPtr->Buffer.Mdl);
		//PVOID pVa = (PUCHAR)MmGetSystemAddressForMdl(dataPtr->Buffer.Mdl) + MmGetMdlByteOffset(dataPtr->Buffer.Mdl);
		PVOID pVa = MmGetMdlVirtualAddress(dataPtr->Buffer.Mdl);
		PVOID pRealVa = (PUCHAR)pVa + +dataPtr->Buffer.Offset;
		RtlCopyMemory((PUCHAR)newEntry->DataBuffer + copyOffset, pRealVa, dataPtr->Buffer.Length);
		copyOffset += dataPtr->Buffer.Length;
		dataPtr = dataPtr->Next;
	}

	KIRQL oldIrql;
	KeAcquireSpinLock(&Queue->Lock, &oldIrql);
	InsertTailList(&Queue->Head, &newEntry->Entry);
	//ExInterlockedInsertTailList(&Queue->Head, &newEntry->Entry, &Queue->Lock);
	Queue->TotalSize += newEntry->Length;
	KeReleaseSpinLock(&Queue->Lock, oldIrql);

	return STATUS_SUCCESS;
}

VOID
RMS_ClearReceivedDataQueue(
	_In_ PRMS_DATA_BUFFER_QUEUE Queue
)
{
	LIST_ENTRY listHead;
	PLIST_ENTRY listEntry;
	KIRQL oldIrql;

	PAGED_CODE();

	//KdBreakPoint();

	if (IsListEmpty(&Queue->Head)) {
		return;
	}

	InitializeListHead(&listHead);
	KeAcquireSpinLock(&Queue->Lock, &oldIrql);
	if (!IsListEmpty(&Queue->Head)) {
		listHead.Blink = Queue->Head.Blink;
		listHead.Flink = Queue->Head.Flink;
		listHead.Blink->Flink = listHead.Flink->Blink = &listHead;
		Queue->Head.Blink = Queue->Head.Flink = &Queue->Head;
		Queue->TotalSize = 0;
	}
	KeReleaseSpinLock(&Queue->Lock, oldIrql);

	while (!IsListEmpty(&listHead)) {
		listEntry = RemoveHeadList(&listHead);

		PRMS_DATA_BUFFER_ENTRY dataBufferEntry = CONTAINING_RECORD(listEntry, RMS_DATA_BUFFER_ENTRY, Entry);

		ExFreePool(dataBufferEntry->DataBuffer);
		ExFreePool(dataBufferEntry);
	}
}

NTSTATUS
WSKAPI
RMS_WskReceiveEvent(
	_In_		PVOID SocketContext,
	_In_		ULONG Flags,
	_In_opt_	PWSK_DATA_INDICATION DataIndication,
	_In_        SIZE_T BytesIndicated,
	_Inout_     SIZE_T* BytesAccepted
)
{
	static SIZE_T packetSize;

	PRMS_SOCKET Socket = SocketContext;
	PRMS_DATA_BUFFER_QUEUE Queue = Socket->ReceivedDataQueue;

	//KdBreakPoint();

	if (!DataIndication) {
		Socket->Connected = FALSE;
		Queue->LastStatus = STATUS_CONNECTION_INVALID;
	} else {
		packetSize += BytesIndicated;
		if (WSK_FLAG_ENTIRE_MESSAGE & Flags) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Packet Size: %llx\n", (UINT64)packetSize);
			packetSize = 0;
		}
		Queue->LastStatus = RMS_EnReceivedDataQueue(Queue, DataIndication, BytesIndicated);
	}

	*BytesAccepted = BytesIndicated;

	return STATUS_SUCCESS;
}

NTSTATUS
WSKAPI
RMS_WskDisconnectEvent(
	_In_ PVOID SocketContext,
	_In_ ULONG Flags
)
{
	PRMS_SOCKET Socket = SocketContext;

	UNREFERENCED_PARAMETER(Flags);

	//KdBreakPoint();

	Socket->Connected = FALSE;

	return STATUS_SUCCESS;
}

NTSTATUS
RMS_WskIoCompletionRoutine(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp,
	_Inout_ PVOID Context
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	KeSetEvent(Context, IO_NETWORK_INCREMENT, FALSE);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

USHORT
Wsk_HTONS(
	_In_ USHORT hs
)
{
	USHORT ret;

	PAGED_CODE();

	((PUCHAR)&ret)[0] = ((PUCHAR)&hs)[1];
	((PUCHAR)&ret)[1] = ((PUCHAR)&hs)[0];

	return ret;
}

USHORT
Wsk_NTOHS(
	_In_ USHORT ns
)
{
	PAGED_CODE();

	return Wsk_HTONS(ns);
}

#ifndef WSK_H
#define WSK_H 1

#include <ntddk.h>

#if !defined(__MINGW64__)
#error                                                                         \
    "This was designed to work **only** with Mingw-w64! For MSVC, please check https://github.com/wbenny/KSOCKET out"
#endif

#if (NTDDI_VERSION < NTDDI_WIN10)
#error                                                                         \
    "Your mingw-w64 toolchain is too old. Please use the one provided by https://github.com/utoni/mingw-w64-ddk-template"
#endif

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error                                                                         \
    "This project requires a little endian system. Does Windows support any other?"
#endif

typedef struct sockaddr_storage {
	char storage[256];	/* hope this is enough */
};

// ---------------------------------------------------------------
// defines
// ---------------------------------------------------------------

#define WSKAPI NTAPI
#define MAKE_WSK_VERSION(Mj, Mn) ((USHORT)((Mj) << 8) | (USHORT)((Mn)&0xff))
#define WSK_NO_WAIT 0
#define WSK_INFINITE_WAIT 0xffffffff

#define WSK_FLAG_BASIC_SOCKET 0x00000000
#define WSK_FLAG_LISTEN_SOCKET 0x00000001
#define WSK_FLAG_CONNECTION_SOCKET 0x00000002
#define WSK_FLAG_DATAGRAM_SOCKET 0x00000004
#define WSK_FLAG_STREAM_SOCKET 0x00000008

#define INADDR_ANY ((ULONG)0x00000000)

// ---------------------------------------------------------------
// forward decls / opaque structs
// ---------------------------------------------------------------

struct _WSK_CLIENT_CONNECTION_DISPATCH;
typedef struct _WSK_CLIENT_CONNECTION_DISPATCH WSK_CLIENT_CONNECTION_DISPATCH;
typedef WSK_CLIENT_CONNECTION_DISPATCH *PWSK_CLIENT_CONNECTION_DISPATCH;
struct _WSK_CLIENT_NPI;
typedef struct _WSK_CLIENT_NPI WSK_CLIENT_NPI;
typedef struct _WSK_CLIENT_NPI *PWSK_CLIENT_NPI;
struct _WSK_PROVIDER_NPI;
typedef struct _WSK_PROVIDER_NPI WSK_PROVIDER_NPI;
typedef struct _WSK_PROVIDER_NPI *PWSK_PROVIDER_NPI;

typedef PVOID PWSK_CLIENT;

// ---------------------------------------------------------------
// enums
// ---------------------------------------------------------------

typedef enum {
  WskSetOption, // set socket option
  WskGetOption, // get socket option
  WskIoctl,     // socket IOCTL
  WskControlMax
} WSK_CONTROL_SOCKET_TYPE,
    *PWSK_CONTROL_SOCKET_TYPE;

enum {
  AI_PASSIVE = 0x01,
  AI_CANONNAME = 0x02,
  AI_NUMERICHOST = 0x04,
  AI_ALL = 0x0100,
  AI_ADDRCONFIG = 0x0400,
  AI_V4MAPPED = 0x0800,
  AI_NON_AUTHORITATIVE = 0x4000,
  AI_SECURE = 0x08000,
  AI_RETURN_PREFERRED_NAMES = 0x10000,
  AI_FQDN = 0x00020000,
  AI_FILESERVER = 0x00040000
};

typedef enum ADDRESS_FAMILY {
  AF_UNSPEC = 0,
  AF_INET = 2,
  AF_INET6 = 23
} ADDRESS_FAMILY;

enum {
  IPPROTO_ICMP = 1,
  IPPROTO_IGMP = 2,
  BTHPROTO_RFCOMM = 3,
  IPPROTO_TCP = 6,
  IPPROTO_UDP = 17,
  IPPROTO_ICMPV6 = 58,
  IPPROTO_RM = 113
};

enum {
  SOCK_STREAM = 1,
  SOCK_DGRAM = 2,
  SOCK_RAW = 3,
  SOCK_RDM = 4,
  SOCK_SEQPACKET = 5,
};

typedef enum {
  WskInspectReject, // reject the connection request
  WskInspectAccept, // proceed with accept
  WskInspectPend,   // delay the decision (use WskInspectComplete later)
  WskInspectMax
} WSK_INSPECT_ACTION,
    *PWSK_INSPECT_ACTION;

// ---------------------------------------------------------------
// general structs
// ---------------------------------------------------------------

typedef struct addrinfo {
  int ai_flags;
  int ai_family;
  int ai_socktype;
  int ai_protocol;
  size_t ai_addrlen;
  char *ai_canonname;
  struct sockaddr *ai_addr;
  struct addrinfo *ai_next;
} ADDRINFOA, *PADDRINFOA;

typedef struct addrinfoexA {
  int ai_flags;
  int ai_family;
  int ai_socktype;
  int ai_protocol;
  size_t ai_addrlen;
  char *ai_canonname;
  struct sockaddr *ai_addr;
  void *ai_blob;
  size_t ai_bloblen;
  LPGUID ai_provider;
  struct addrinfoexA *ai_next;
} ADDRINFOEXA, *PADDRINFOEXA, *LPADDRINFOEXA;

typedef struct addrinfoW {
  int ai_flags;
  int ai_family;
  int ai_socktype;
  int ai_protocol;
  size_t ai_addrlen;
  PWSTR ai_canonname;
  struct sockaddr *ai_addr;
  struct addrinfoW *ai_next;
} ADDRINFOW, *PADDRINFOW;

typedef struct addrinfoexW {
  int ai_flags;
  int ai_family;
  int ai_socktype;
  int ai_protocol;
  size_t ai_addrlen;
  PWSTR ai_canonname;
  struct sockaddr *ai_addr;
  void *ai_blob;
  size_t ai_bloblen;
  LPGUID ai_provider;
  struct addrinfoexW *ai_next;
} ADDRINFOEXW, *PADDRINFOEXW, *LPADDRINFOEXW;

typedef struct sockaddr {
  ADDRESS_FAMILY sa_family;
  CHAR sa_data[14];
} SOCKADDR, *PSOCKADDR, *LPSOCKADDR;

struct in_addr {
  union {
    struct {
      UCHAR s_b1;
      UCHAR s_b2;
      UCHAR s_b3;
      UCHAR s_b4;
    } s_un_b;
    struct {
      USHORT s_w1;
      USHORT s_w2;
    } s_un_w;
    ULONG s_addr;
  };
};

typedef struct sockaddr_in {
  short sin_family;
  USHORT sin_port;
  struct in_addr sin_addr;
  char sin_zero[8];
} SOCKADDR_IN, *PSOCKADDR_IN, *LPSOCKADDR_IN;

typedef struct _WSK_SOCKET {
  const VOID *Dispatch;
} WSK_SOCKET, *PWSK_SOCKET;

typedef struct _WSK_BUF {
  PMDL Mdl;      // Locked MDL chain
  ULONG Offset;  // Offset into the "first" Mdl in the chain
  SIZE_T Length; // Length of data starting from Offset
} WSK_BUF, *PWSK_BUF;

typedef struct _WSK_BUF_LIST {
  struct _WSK_BUF_LIST *Next;
  WSK_BUF Buffer;
} WSK_BUF_LIST, *PWSK_BUF_LIST;

typedef struct _WSK_DATA_INDICATION {
  struct _WSK_DATA_INDICATION *Next;
  WSK_BUF Buffer;
} WSK_DATA_INDICATION, *PWSK_DATA_INDICATION;

typedef struct _WSK_INSPECT_ID {
  ULONG_PTR Key;
  ULONG SerialNumber;
} WSK_INSPECT_ID, *PWSK_INSPECT_ID;

typedef struct _WSACMSGHDR {
  SIZE_T cmsg_len;
  INT cmsg_level;
  INT cmsg_type;
} WSACMSGHDR, *PWSACMSGHDR, *LPWSACMSGHDR, CMSGHDR, *PCMSGHDR;

typedef struct _WSK_DATAGRAM_INDICATION {
  struct _WSK_DATAGRAM_INDICATION *Next;
  WSK_BUF Buffer;
  _Field_size_bytes_(ControlInfoLength) PCMSGHDR ControlInfo;
  ULONG ControlInfoLength;
  PSOCKADDR RemoteAddress;
} WSK_DATAGRAM_INDICATION, *PWSK_DATAGRAM_INDICATION;

typedef struct _WSK_REGISTRATION {
  ULONGLONG ReservedRegistrationState;
  PVOID ReservedRegistrationContext;
  KSPIN_LOCK ReservedRegistrationLock;
} WSK_REGISTRATION, *PWSK_REGISTRATION;

// ---------------------------------------------------------------
// callback functions
// ---------------------------------------------------------------

typedef NTSTATUS(WSKAPI *PFN_WSK_CONTROL_SOCKET)(
    _In_ PWSK_SOCKET Socket, _In_ WSK_CONTROL_SOCKET_TYPE RequestType,
    _In_ ULONG ControlCode, _In_ ULONG Level, _In_ SIZE_T InputSize,
    _In_opt_ PVOID InputBuffer, _In_ SIZE_T OutputSize,
    _Out_opt_ PVOID OutputBuffer, _Out_opt_ SIZE_T *OutputSizeReturned,
    _In_ _Out_ PIRP Irp);
typedef NTSTATUS(WSKAPI *PFN_WSK_CLOSE_SOCKET)(_In_ PWSK_SOCKET Socket,
                                               _Inout_ PIRP Irp);

typedef NTSTATUS(WSKAPI *PFN_WSK_CONNECT)(_In_ PWSK_SOCKET Socket,
                                          _In_ PSOCKADDR RemoteAddress,
                                          ULONG Flags, _In_ _Out_ PIRP Irp);
typedef NTSTATUS(WSKAPI *PFN_WSK_BIND)(_In_ PWSK_SOCKET Socket,
                                       _In_ PSOCKADDR LocalAddress,
                                       _Reserved_ ULONG Flags,
                                       _Inout_ PIRP Irp);
typedef NTSTATUS(WSKAPI *PFN_WSK_GET_LOCAL_ADDRESS)(
    _In_ PWSK_SOCKET Socket, _Out_ PSOCKADDR LocalAddress, _Inout_ PIRP Irp);
typedef NTSTATUS(WSKAPI *PFN_WSK_GET_REMOTE_ADDRESS)(
    _In_ PWSK_SOCKET Socket, _Out_ PSOCKADDR RemoteAddress, _Inout_ PIRP Irp);
typedef NTSTATUS(WSKAPI *PFN_WSK_SEND)(_In_ PWSK_SOCKET Socket,
                                       _In_ PWSK_BUF Buffer, _In_ ULONG Flags,
                                       _Inout_ PIRP Irp);
typedef NTSTATUS(WSKAPI *PFN_WSK_RECEIVE)(_In_ PWSK_SOCKET Socket,
                                          _In_ PWSK_BUF Buffer,
                                          _In_ ULONG Flags, _Inout_ PIRP Irp);
typedef NTSTATUS(WSKAPI *PFN_WSK_DISCONNECT)(_In_ PWSK_SOCKET Socket,
                                             _In_opt_ PWSK_BUF Buffer,
                                             _In_ ULONG Flags,
                                             _Inout_ PIRP Irp);
typedef NTSTATUS(WSKAPI *PFN_WSK_RELEASE_DATA_INDICATION_LIST)(
    _In_ PWSK_SOCKET Socket, _In_ PWSK_DATA_INDICATION DataIndication);
typedef NTSTATUS(WSKAPI *PFN_WSK_CONNECT_EX)(_In_ PWSK_SOCKET Socket,
                                             _In_ PSOCKADDR RemoteAddress,
                                             _In_opt_ PWSK_BUF Buffer,
                                             _Reserved_ ULONG Flags,
                                             _Inout_ PIRP Irp);
typedef NTSTATUS(WSKAPI *PFN_WSK_CONNECT_EX)(_In_ PWSK_SOCKET Socket,
                                             _In_ PSOCKADDR RemoteAddress,
                                             _In_opt_ PWSK_BUF Buffer,
                                             _Reserved_ ULONG Flags,
                                             _Inout_ PIRP Irp);
typedef void *PFN_WSK_SEND_EX;    // reserved for system use
typedef void *PFN_WSK_RECEIVE_EX; // reserved for system use
typedef _At_(Irp->IoStatus.Information, __drv_allocatesMem(Mem))
    NTSTATUS(WSKAPI *PFN_WSK_ACCEPT)(
        _In_ PWSK_SOCKET ListenSocket, _Reserved_ ULONG Flags,
        _In_opt_ PVOID AcceptSocketContext,
        _In_opt_ CONST WSK_CLIENT_CONNECTION_DISPATCH *AcceptSocketDispatch,
        _Out_opt_ PSOCKADDR LocalAddress, _Out_opt_ PSOCKADDR RemoteAddress,
        _Inout_ PIRP Irp);
typedef _Must_inspect_result_ NTSTATUS(WSKAPI *PFN_WSK_RECEIVE_EVENT)(
    _In_opt_ PVOID SocketContext, _In_ ULONG Flags,
    _In_opt_ PWSK_DATA_INDICATION DataIndication, _In_ SIZE_T BytesIndicated,
    _Inout_ SIZE_T *BytesAccepted);
typedef NTSTATUS(WSKAPI *PFN_WSK_DISCONNECT_EVENT)(_In_opt_ PVOID SocketContext,
                                                   _In_ ULONG Flags);
typedef NTSTATUS(WSKAPI *PFN_WSK_SEND_BACKLOG_EVENT)(
    _In_opt_ PVOID SocketContext, _In_ SIZE_T IdealBacklogSize);
typedef NTSTATUS(WSKAPI *PFN_WSK_INSPECT_COMPLETE)(
    _In_ PWSK_SOCKET ListenSocket, _In_ PWSK_INSPECT_ID InspectID,
    _In_ WSK_INSPECT_ACTION Action, _Inout_ PIRP Irp);
typedef NTSTATUS(WSKAPI *PFN_WSK_SEND_TO)(
    _In_ PWSK_SOCKET Socket, _In_ PWSK_BUF Buffer, _Reserved_ ULONG Flags,
    _In_opt_ PSOCKADDR RemoteAddress, _In_ ULONG ControlInfoLength,
    _In_reads_bytes_opt_(ControlInfoLength) PCMSGHDR ControlInfo,
    _Inout_ PIRP Irp);
typedef _Must_inspect_result_ NTSTATUS(WSKAPI *PFN_WSK_RECEIVE_FROM_EVENT)(
    _In_opt_ PVOID SocketContext, _In_ ULONG Flags,
    _In_opt_ PWSK_DATAGRAM_INDICATION DataIndication);
typedef NTSTATUS(WSKAPI *PFN_WSK_RECEIVE_FROM)(
    _In_ PWSK_SOCKET Socket, _In_ PWSK_BUF Buffer, _Reserved_ ULONG Flags,
    _Out_opt_ PSOCKADDR RemoteAddress, _Inout_ PULONG ControlLength,
    _Out_writes_bytes_opt_(*ControlLength) PCMSGHDR ControlInfo,
    _Out_opt_ PULONG ControlFlags, _Inout_ PIRP Irp);
typedef NTSTATUS(WSKAPI *PFN_WSK_RELEASE_DATAGRAM_INDICATION_LIST)(
    _In_ PWSK_SOCKET Socket, _In_ PWSK_DATAGRAM_INDICATION DatagramIndication);
typedef NTSTATUS(WSKAPI *PFN_WSK_SEND_MESSAGES)(
    _In_ PWSK_SOCKET Socket, _In_ PWSK_BUF_LIST BufferList,
    _Reserved_ ULONG Flags, _In_opt_ PSOCKADDR RemoteAddress,
    _In_ ULONG ControlInfoLength,
    _In_reads_bytes_opt_(ControlInfoLength) PCMSGHDR ControlInfo,
    _Inout_ PIRP Irp);
typedef _At_((void *)Irp->IoStatus.Information, __drv_allocatesMem(Mem))
    NTSTATUS(WSKAPI *PFN_WSK_SOCKET)(
        _In_ PWSK_CLIENT Client, _In_ ADDRESS_FAMILY AddressFamily,
        _In_ USHORT SocketType, _In_ ULONG Protocol, _In_ ULONG Flags,
        _In_opt_ PVOID SocketContext, _In_opt_ CONST VOID *Dispatch,
        _In_opt_ PEPROCESS OwningProcess, _In_opt_ PETHREAD OwningThread,
        _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor, _Inout_ PIRP Irp);
typedef _At_(Irp->IoStatus.Information, __drv_allocatesMem(Mem))
    NTSTATUS(WSKAPI *PFN_WSK_SOCKET_CONNECT)(
        _In_ PWSK_CLIENT Client, _In_ USHORT SocketType, _In_ ULONG Protocol,
        _In_ PSOCKADDR LocalAddress, _In_ PSOCKADDR RemoteAddress,
        _Reserved_ ULONG Flags, _In_opt_ PVOID SocketContext,
        _In_opt_ CONST WSK_CLIENT_CONNECTION_DISPATCH *Dispatch,
        _In_opt_ PEPROCESS OwningProcess, _In_opt_ PETHREAD OwningThread,
        _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor, _Inout_ PIRP Irp);
typedef NTSTATUS(WSKAPI *PFN_WSK_CONTROL_CLIENT)(
    _In_ PWSK_CLIENT Client, _In_ ULONG ControlCode, _In_ SIZE_T InputSize,
    _In_reads_bytes_opt_(InputSize) PVOID InputBuffer, _In_ SIZE_T OutputSize,
    _Out_writes_bytes_opt_(OutputSize) PVOID OutputBuffer,
    _Out_opt_ SIZE_T *OutputSizeReturned, _Inout_opt_ PIRP Irp);
typedef _At_(*Result, __drv_allocatesMem(Mem))
    NTSTATUS(WSKAPI *PFN_WSK_GET_ADDRESS_INFO)(
        _In_ PWSK_CLIENT Client, _In_opt_ PUNICODE_STRING NodeName,
        _In_opt_ PUNICODE_STRING ServiceName, _In_opt_ ULONG NameSpace,
        _In_opt_ GUID *Provider, _In_opt_ PADDRINFOEXW Hints,
        _Outptr_ PADDRINFOEXW *Result, _In_opt_ PEPROCESS OwningProcess,
        _In_opt_ PETHREAD OwningThread, _Inout_ PIRP Irp);
typedef _At_(AddrInfo, __drv_freesMem(Mem))
    VOID(WSKAPI *PFN_WSK_FREE_ADDRESS_INFO)(_In_ PWSK_CLIENT Client,
                                            _In_ PADDRINFOEXW AddrInfo);
typedef NTSTATUS(WSKAPI *PFN_WSK_GET_NAME_INFO)(
    _In_ PWSK_CLIENT Client, _In_ PSOCKADDR SockAddr, _In_ ULONG SockAddrLength,
    _Out_opt_ PUNICODE_STRING NodeName, _Out_opt_ PUNICODE_STRING ServiceName,
    _In_ ULONG Flags, _In_opt_ PEPROCESS OwningProcess,
    _In_opt_ PETHREAD OwningThread, _Inout_ PIRP Irp);
typedef NTSTATUS(WSKAPI *PFN_WSK_CLIENT_EVENT)(
    _In_opt_ PVOID ClientContext, _In_ ULONG EventType,
    _In_reads_bytes_opt_(InformationLength) PVOID Information,
    _In_ SIZE_T InformationLength);
_Must_inspect_result_ NTSTATUS WskRegister(
    _In_ PWSK_CLIENT_NPI WskClientNpi, _Out_ PWSK_REGISTRATION WskRegistration);
_Must_inspect_result_ NTSTATUS WskCaptureProviderNPI(
    _In_ PWSK_REGISTRATION WskRegistration, _In_ ULONG WaitTimeout,
    _Out_ PWSK_PROVIDER_NPI WskProviderNpi);
VOID WskReleaseProviderNPI(_In_ PWSK_REGISTRATION WskRegistration);
VOID WskDeregister(_In_ PWSK_REGISTRATION WskRegistration);

// ---------------------------------------------------------------
// function pointer structs
// ---------------------------------------------------------------

typedef struct _WSK_CLIENT_CONNECTION_DISPATCH {
  PFN_WSK_RECEIVE_EVENT WskReceiveEvent;
  PFN_WSK_DISCONNECT_EVENT WskDisconnectEvent;
  PFN_WSK_SEND_BACKLOG_EVENT WskSendBacklogEvent;
} WSK_CLIENT_CONNECTION_DISPATCH, *PWSK_CLIENT_CONNECTION_DISPATCH;

typedef struct _WSK_PROVIDER_BASIC_DISPATCH {
  PFN_WSK_CONTROL_SOCKET WskControlSocket;
  PFN_WSK_CLOSE_SOCKET WskCloseSocket;
} WSK_PROVIDER_BASIC_DISPATCH, *PWSK_PROVIDER_BASIC_DISPATCH;

typedef struct _WSK_PROVIDER_CONNECTION_DISPATCH {
#ifdef __cplusplus
  WSK_PROVIDER_BASIC_DISPATCH Basic;
#else
  WSK_PROVIDER_BASIC_DISPATCH;
#endif
  PFN_WSK_BIND WskBind;
  PFN_WSK_CONNECT WskConnect;
  PFN_WSK_GET_LOCAL_ADDRESS WskGetLocalAddress;
  PFN_WSK_GET_REMOTE_ADDRESS WskGetRemoteAddress;
  PFN_WSK_SEND WskSend;
  PFN_WSK_RECEIVE WskReceive;
  PFN_WSK_DISCONNECT WskDisconnect;
  PFN_WSK_RELEASE_DATA_INDICATION_LIST WskRelease;
  PFN_WSK_CONNECT_EX WskConnectEx;
  PFN_WSK_SEND_EX WskSendEx;
  PFN_WSK_RECEIVE_EX WskReceiveEx;
} WSK_PROVIDER_CONNECTION_DISPATCH, *PWSK_PROVIDER_CONNECTION_DISPATCH;

typedef struct _WSK_PROVIDER_LISTEN_DISPATCH {
#ifdef __cplusplus
  WSK_PROVIDER_BASIC_DISPATCH Basic;
#else
  WSK_PROVIDER_BASIC_DISPATCH;
#endif
  PFN_WSK_BIND WskBind;
  PFN_WSK_ACCEPT WskAccept;
  PFN_WSK_INSPECT_COMPLETE WskInspectComplete;
  PFN_WSK_GET_LOCAL_ADDRESS WskGetLocalAddress;
} WSK_PROVIDER_LISTEN_DISPATCH, *PWSK_PROVIDER_LISTEN_DISPATCH;

typedef struct _WSK_PROVIDER_DATAGRAM_DISPATCH {
#ifdef __cplusplus
  WSK_PROVIDER_BASIC_DISPATCH Basic;
#else
  WSK_PROVIDER_BASIC_DISPATCH;
#endif
  PFN_WSK_BIND WskBind;
  PFN_WSK_SEND_TO WskSendTo;
  PFN_WSK_RECEIVE_FROM WskReceiveFrom;
  PFN_WSK_RELEASE_DATAGRAM_INDICATION_LIST WskRelease;
  PFN_WSK_GET_LOCAL_ADDRESS WskGetLocalAddress;
  PFN_WSK_SEND_MESSAGES WskSendMessages;
} WSK_PROVIDER_DATAGRAM_DISPATCH, *PWSK_PROVIDER_DATAGRAM_DISPATCH;

typedef struct _WSK_PROVIDER_DISPATCH {
  USHORT Version;
  USHORT Reserved;
  PFN_WSK_SOCKET WskSocket;
  PFN_WSK_SOCKET_CONNECT WskSocketConnect;
  PFN_WSK_CONTROL_CLIENT WskControlClient;
  PFN_WSK_GET_ADDRESS_INFO WskGetAddressInfo;
  PFN_WSK_FREE_ADDRESS_INFO WskFreeAddressInfo;
  PFN_WSK_GET_NAME_INFO WskGetNameInfo;
} WSK_PROVIDER_DISPATCH, *PWSK_PROVIDER_DISPATCH;

typedef struct _WSK_CLIENT_DISPATCH {
  USHORT Version;
  USHORT Reserved;
  PFN_WSK_CLIENT_EVENT WskClientEvent;
} WSK_CLIENT_DISPATCH, *PWSK_CLIENT_DISPATCH;

typedef struct _WSK_CLIENT_NPI {
  PVOID ClientContext;
  CONST WSK_CLIENT_DISPATCH *Dispatch;
} WSK_CLIENT_NPI, *PWSK_CLIENT_NPI;

typedef struct _WSK_PROVIDER_NPI {
  PWSK_CLIENT Client;
  CONST WSK_PROVIDER_DISPATCH *Dispatch;
} WSK_PROVIDER_NPI, *PWSK_PROVIDER_NPI;

#endif

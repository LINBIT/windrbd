/*
 * winnt.h
 *
 * Windows NT native definitions for user mode
 *
 * This file is part of the ReactOS PSDK package.
 *
 * This file is auto-generated from ReactOS XDK.
 *
 * THIS SOFTWARE IS NOT COPYRIGHTED
 *
 * This source code is offered for use in the public domain. You may
 * use, modify or distribute it freely.
 *
 * This code is distributed in the hope that it will be useful but
 * WITHOUT ANY WARRANTY. ALL WARRANTIES, EXPRESS OR IMPLIED ARE HEREBY
 * DISCLAIMED. This includes but is not limited to warranties of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#pragma once
#ifndef _WINNT_
#define _WINNT_

/* We require WDK / VS 2008 or newer */
#if defined(_MSC_VER) && (_MSC_VER < 1500)
#error Compiler too old!
#endif

#if defined(__LP64__) || (!defined(_M_AMD64) && defined(__WINESRC__))
#if !defined(__ROS_LONG64__)
#define __ROS_LONG64__
#endif
#endif

#include <ctype.h>
//#include <winapifamily.h>
#ifdef __GNUC__
#include <msvctarget.h>
#endif
#include <specstrings.h>
#include <kernelspecs.h>

#include <excpt.h>
#include <basetsd.h>
#include <guiddef.h>
#include <intrin.h>

#undef __need_wchar_t
#include <winerror.h>
#include <stddef.h>
#include <sdkddkver.h>
#ifndef RC_INVOKED
#include <string.h>
#endif

/* Silence some MSVC warnings */
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4201)
#pragma warning(disable:4214)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Defines the "size" of an any-size array */
#ifndef ANYSIZE_ARRAY
#define ANYSIZE_ARRAY 1
#endif

/* Helper macro to enable gcc's extension.  */
#ifndef __GNU_EXTENSION
 #ifdef __GNUC__
  #define __GNU_EXTENSION __extension__
 #else
  #define __GNU_EXTENSION
 #endif
#endif /* __GNU_EXTENSION */

#ifndef DUMMYUNIONNAME
 #if defined(NONAMELESSUNION)// || !defined(_MSC_EXTENSIONS)
  #define _ANONYMOUS_UNION
  #define _UNION_NAME(x) x
  #define DUMMYUNIONNAME  u
  #define DUMMYUNIONNAME1 u1
  #define DUMMYUNIONNAME2 u2
  #define DUMMYUNIONNAME3 u3
  #define DUMMYUNIONNAME4 u4
  #define DUMMYUNIONNAME5 u5
  #define DUMMYUNIONNAME6 u6
  #define DUMMYUNIONNAME7 u7
  #define DUMMYUNIONNAME8 u8
  #define DUMMYUNIONNAME9  u9
 #else
  #define _ANONYMOUS_UNION __GNU_EXTENSION
  #define _UNION_NAME(x)
  #define DUMMYUNIONNAME
  #define DUMMYUNIONNAME1
  #define DUMMYUNIONNAME2
  #define DUMMYUNIONNAME3
  #define DUMMYUNIONNAME4
  #define DUMMYUNIONNAME5
  #define DUMMYUNIONNAME6
  #define DUMMYUNIONNAME7
  #define DUMMYUNIONNAME8
  #define DUMMYUNIONNAME9
 #endif /* NONAMELESSUNION */
#endif /* !DUMMYUNIONNAME */

#ifndef DUMMYSTRUCTNAME
 #if defined(NONAMELESSUNION)// || !defined(_MSC_EXTENSIONS)
  #define _ANONYMOUS_STRUCT
  #define _STRUCT_NAME(x) x
  #define DUMMYSTRUCTNAME s
  #define DUMMYSTRUCTNAME1 s1
  #define DUMMYSTRUCTNAME2 s2
  #define DUMMYSTRUCTNAME3 s3
  #define DUMMYSTRUCTNAME4 s4
  #define DUMMYSTRUCTNAME5 s5
 #else
  #define _ANONYMOUS_STRUCT __GNU_EXTENSION
  #define _STRUCT_NAME(x)
  #define DUMMYSTRUCTNAME
  #define DUMMYSTRUCTNAME1
  #define DUMMYSTRUCTNAME2
  #define DUMMYSTRUCTNAME3
  #define DUMMYSTRUCTNAME4
  #define DUMMYSTRUCTNAME5
 #endif /* NONAMELESSUNION */
#endif /* DUMMYSTRUCTNAME */

#if defined(STRICT_GS_ENABLED)
 #pragma strict_gs_check(push, on)
#endif

#if defined(_M_MRX000) || defined(_M_ALPHA) || defined(_M_PPC) || defined(_M_IA64) || defined(_M_AMD64) || defined(_M_ARM) || defined(_M_ARM64)
 #define ALIGNMENT_MACHINE
 #define UNALIGNED __unaligned
 #if defined(_WIN64)
  #define UNALIGNED64 __unaligned
 #else
  #define UNALIGNED64
 #endif
#else
 #undef ALIGNMENT_MACHINE
 #define UNALIGNED
 #define UNALIGNED64
#endif

#if defined(_WIN64) || defined(_M_ALPHA)
 #define MAX_NATURAL_ALIGNMENT sizeof(ULONGLONG)
 #define MEMORY_ALLOCATION_ALIGNMENT 16
#else
 #define MAX_NATURAL_ALIGNMENT sizeof(DWORD)
 #define MEMORY_ALLOCATION_ALIGNMENT 8
#endif

/* C99 restrict support */
#if defined(ENABLE_RESTRICTED) && defined(_M_MRX000) && !defined(MIDL_PASS) && !defined(RC_INVOKED)
 #define RESTRICTED_POINTER __restrict
#else
 #define RESTRICTED_POINTER
#endif

/* Returns the base address of a structure from a structure member */
#ifndef CONTAINING_RECORD
 #define CONTAINING_RECORD(address, type, field) \
   ((type *)(((ULONG_PTR)address) - (ULONG_PTR)(&(((type *)0)->field))))
#endif

/* Returns the byte offset of the specified structure's member */
#if !defined(__GNUC__) && !defined(__clang__)
 #define FIELD_OFFSET(Type, Field) ((LONG)(LONG_PTR)&(((Type*) 0)->Field))
#else
 #define FIELD_OFFSET(Type, Field) ((LONG)__builtin_offsetof(Type, Field))
#endif /* __GNUC__ */

/* Returns the type's alignment */
#if defined(_MSC_VER)
 #define TYPE_ALIGNMENT(t) __alignof(t)
#else
 #define TYPE_ALIGNMENT(t) FIELD_OFFSET(struct { char x; t test; }, test)
#endif /* _MSC_VER */

#if defined(_AMD64_) || defined(_X86_)
 #define PROBE_ALIGNMENT(_s) TYPE_ALIGNMENT(DWORD)
#elif defined(_IA64_) || defined(_ARM_) || defined(_ARM64_)
 #define PROBE_ALIGNMENT(_s) max((TYPE_ALIGNMENT(_s), TYPE_ALIGNMENT(DWORD))
#elif !defined(RC_INVOKED)
 #error "Unknown architecture"
#endif

#if defined(_WIN64)
 #define PROBE_ALIGNMENT32(_s) TYPE_ALIGNMENT(DWORD)
#endif /* _WIN64 */

#ifdef __cplusplus
 #define EXTERN_C extern "C"
#else
 #define EXTERN_C extern
#endif /* __cplusplus */

#define NTAPI __stdcall

#ifndef STDMETHODCALLTYPE
 #define STDMETHODCALLTYPE  __stdcall
 #define STDMETHODVCALLTYPE __cdecl
 #define STDAPICALLTYPE     __stdcall
 #define STDAPIVCALLTYPE    __cdecl
 #define STDAPI             EXTERN_C HRESULT STDAPICALLTYPE
 #define STDAPI_(t)         EXTERN_C t STDAPICALLTYPE
 #define STDMETHODIMP       HRESULT STDMETHODCALLTYPE
 #define STDMETHODIMP_(t)   t STDMETHODCALLTYPE
 #define STDAPIV            EXTERN_C HRESULT STDAPIVCALLTYPE
 #define STDAPIV_(t)        EXTERN_C t STDAPIVCALLTYPE
 #define STDMETHODIMPV      HRESULT STDMETHODVCALLTYPE
 #define STDMETHODIMPV_(t)  t STDMETHODVCALLTYPE
#endif /* !STDMETHODCALLTYPE */

#define STDOVERRIDEMETHODIMP      __override STDMETHODIMP
#define STDOVERRIDEMETHODIMP_(t)  __override STDMETHODIMP_(t)
#define IFACEMETHODIMP            __override STDMETHODIMP
#define IFACEMETHODIMP_(t)        __override STDMETHODIMP_(t)
#define STDOVERRIDEMETHODIMPV     __override STDMETHODIMPV
#define STDOVERRIDEMETHODIMPV_(t) __override STDMETHODIMPV_(t)
#define IFACEMETHODIMPV           __override STDMETHODIMPV
#define IFACEMETHODIMPV_(t)       __override STDMETHODIMPV_(t)

/* Import and Export Specifiers */

#ifndef DECLSPEC_IMPORT
 #define DECLSPEC_IMPORT __declspec(dllimport) // MIDL?
#endif /* DECLSPEC_IMPORT */

#ifndef DECLSPEC_EXPORT
 #if defined(__REACTOS__) || defined(__WINESRC__)
  #define DECLSPEC_EXPORT __declspec(dllexport)
 #endif
#endif /* DECLSPEC_EXPORT */

#define DECLSPEC_NORETURN __declspec(noreturn)

#ifndef DECLSPEC_ADDRSAFE
 #if defined(_MSC_VER) && (defined(_M_ALPHA) || defined(_M_AXP64))
  #define DECLSPEC_ADDRSAFE __declspec(address_safe)
 #else
  #define DECLSPEC_ADDRSAFE
 #endif
#endif /* DECLSPEC_ADDRSAFE */

#ifndef DECLSPEC_NOTHROW
 #if !defined(MIDL_PASS)
  #define DECLSPEC_NOTHROW __declspec(nothrow)
 #else
  #define DECLSPEC_NOTHROW
 #endif
#endif /* DECLSPEC_NOTHROW */

#ifndef NOP_FUNCTION
 #if defined(_MSC_VER)
  #define NOP_FUNCTION __noop
 #else
  #define NOP_FUNCTION (void)0
 #endif
#endif /* NOP_FUNCTION */

#if !defined(_NTSYSTEM_)
 #define NTSYSAPI     DECLSPEC_IMPORT
 #define NTSYSCALLAPI DECLSPEC_IMPORT
#else
 #define NTSYSAPI
 #if defined(_NTDLLBUILD_)
  #define NTSYSCALLAPI
 #else
  #define NTSYSCALLAPI DECLSPEC_ADDRSAFE
 #endif
#endif /* _NTSYSTEM_ */

/* Inlines */
#ifndef FORCEINLINE
 #define FORCEINLINE __forceinline
#endif /* FORCEINLINE */

#ifndef DECLSPEC_NOINLINE
 #if (_MSC_VER >= 1300)
  #define DECLSPEC_NOINLINE  __declspec(noinline)
 #elif defined(__GNUC__)
  #define DECLSPEC_NOINLINE __attribute__((noinline))
 #else
  #define DECLSPEC_NOINLINE
 #endif
#endif /* DECLSPEC_NOINLINE */

#if !defined(_M_CEE_PURE)
 #define NTAPI_INLINE NTAPI
#else
 #define NTAPI_INLINE
#endif /* _M_CEE_PURE */

/* Use to specify structure alignment. Note: VS and GCC behave slightly
   different. Therefore it is important to stick to the following rules:
   - If you want a struct to be aligned, put DECLSPEC_ALIGN after "struct":
     "typedef struct DECLSPEC_ALIGN(16) _FOO { ... } FOO, *PFOO;"
     _alignof(PFOO) is sizeof(void*) here as usual.
   - If you don't want the struct, but only the typedef to be aligned,
     use an extra typedef.
     struct _BAR { ... };
     typedef DECLSPEC_ALIGN(16) struct _BAR BAR, *ALIGNEDPBAR;
     _alignof(ALIGNEDPBAR) is 16 now! */
#ifndef DECLSPEC_ALIGN
 #if defined(_MSC_VER) && !defined(MIDL_PASS)
  #define DECLSPEC_ALIGN(x) __declspec(align(x))
 #elif defined(__GNUC__)
  #define DECLSPEC_ALIGN(x) __attribute__((aligned(x)))
 #else
  #define DECLSPEC_ALIGN(x)
 #endif
#endif /* DECLSPEC_ALIGN */

#ifndef SYSTEM_CACHE_ALIGNMENT_SIZE
 #if defined(_AMD64_) || defined(_X86_)
  #define SYSTEM_CACHE_ALIGNMENT_SIZE 64
 #else
  #define SYSTEM_CACHE_ALIGNMENT_SIZE 128
 #endif
#endif /* SYSTEM_CACHE_ALIGNMENT_SIZE */

#ifndef DECLSPEC_CACHEALIGN
 #define DECLSPEC_CACHEALIGN DECLSPEC_ALIGN(SYSTEM_CACHE_ALIGNMENT_SIZE)
#endif /* DECLSPEC_CACHEALIGN */

#ifndef DECLSPEC_UUID
 #if defined(_MSC_VER) && defined(__cplusplus)
  #define DECLSPEC_UUID(x) __declspec(uuid(x))
 #else
  #define DECLSPEC_UUID(x)
 #endif
#endif /* DECLSPEC_UUID */

#ifndef DECLSPEC_NOVTABLE
 #if defined(_MSC_VER) && defined(__cplusplus)
  #define DECLSPEC_NOVTABLE __declspec(novtable)
 #else
  #define DECLSPEC_NOVTABLE
 #endif
#endif /* DECLSPEC_NOVTABLE */

#ifndef DECLSPEC_SELECTANY
 #if defined(_MSC_VER) || defined(__GNUC__)
  #define DECLSPEC_SELECTANY __declspec(selectany)
 #else
  #define DECLSPEC_SELECTANY
 #endif
#endif /* DECLSPEC_SELECTANY */

#ifndef DECLSPEC_DEPRECATED
 #if (defined(_MSC_VER) || defined(__GNUC__)) && !defined(MIDL_PASS)
  #define DECLSPEC_DEPRECATED __declspec(deprecated)
  #define DEPRECATE_SUPPORTED
 #else
  #define DECLSPEC_DEPRECATED
  #undef  DEPRECATE_SUPPORTED
 #endif
#endif /* DECLSPEC_DEPRECATED */

#ifdef DEPRECATE_DDK_FUNCTIONS
 #ifdef _NTDDK_
  #define DECLSPEC_DEPRECATED_DDK DECLSPEC_DEPRECATED
  #ifdef DEPRECATE_SUPPORTED
   #define PRAGMA_DEPRECATED_DDK 1
  #endif
 #else
  #define DECLSPEC_DEPRECATED_DDK
  #define PRAGMA_DEPRECATED_DDK 1
 #endif
#else
 #define DECLSPEC_DEPRECATED_DDK
 #define PRAGMA_DEPRECATED_DDK 0
#endif /* DEPRECATE_DDK_FUNCTIONS */

/* Use to silence unused variable warnings when it is intentional */
#define UNREFERENCED_PARAMETER(P) ((void)(P))
#define DBG_UNREFERENCED_PARAMETER(P) ((void)(P))
#define DBG_UNREFERENCED_LOCAL_VARIABLE(L) ((void)(L))

/* Void Pointers */
typedef void *PVOID;
typedef void * POINTER_64 PVOID64;

/* Handle Type */
typedef void *HANDLE, **PHANDLE;
#ifdef STRICT
 #define DECLARE_HANDLE(n) typedef struct n##__{int unused;} *n
#else
 #define DECLARE_HANDLE(n) typedef HANDLE n
#endif

/* Upper-Case Versions of Some Standard C Types */
#ifndef VOID
 #define VOID void
 typedef char CHAR;
 typedef short SHORT;

 #if defined(__ROS_LONG64__)
  typedef int LONG;
 #else
  typedef long LONG;
 #endif

 #if !defined(MIDL_PASS)
 typedef int INT;
 #endif /* !MIDL_PASS */
#endif /* VOID */


/* Signed Types */
typedef SHORT *PSHORT;
typedef LONG *PLONG;

/* Flag types */
typedef unsigned char FCHAR;
typedef unsigned short FSHORT;
typedef unsigned long FLONG;

typedef unsigned char BOOLEAN, *PBOOLEAN;

#ifndef _HRESULT_DEFINED
 #define _HRESULT_DEFINED
 typedef _Return_type_success_(return >= 0) LONG HRESULT;
#endif /* _HRESULT_DEFINED */

/* 64-bit types */
#define _ULONGLONG_
__GNU_EXTENSION typedef __int64 LONGLONG, *PLONGLONG;
__GNU_EXTENSION typedef unsigned __int64 ULONGLONG, *PULONGLONG;
#define _DWORDLONG_
typedef ULONGLONG DWORDLONG, *PDWORDLONG;

/* Update Sequence Number */
typedef LONGLONG USN;

/* ANSI (Multi-byte Character) types */
typedef CHAR *PCHAR, *LPCH, *PCH, *PNZCH;
typedef CONST CHAR *LPCCH, *PCCH, *PCNZCH;
typedef _Null_terminated_ CHAR *NPSTR, *LPSTR, *PSTR;
typedef _Null_terminated_ PSTR *PZPSTR;
typedef _Null_terminated_ CONST PSTR *PCZPSTR;
typedef _Null_terminated_ CONST CHAR *LPCSTR, *PCSTR;
typedef _Null_terminated_ PCSTR *PZPCSTR;

typedef _NullNull_terminated_ CHAR *PZZSTR;
typedef _NullNull_terminated_ CONST CHAR *PCZZSTR;


/* UNICODE (Wide Character) types */
typedef wchar_t WCHAR;
typedef WCHAR *PWCHAR, *LPWCH, *PWCH;
typedef CONST WCHAR *LPCWCH, *PCWCH;
typedef _Null_terminated_ WCHAR *NWPSTR, *LPWSTR, *PWSTR;
typedef _Null_terminated_ PWSTR *PZPWSTR;
typedef _Null_terminated_ CONST PWSTR *PCZPWSTR;
typedef _Null_terminated_ WCHAR UNALIGNED *LPUWSTR, *PUWSTR;
typedef _Null_terminated_ CONST WCHAR *LPCWSTR, *PCWSTR;
typedef _Null_terminated_ PCWSTR *PZPCWSTR;
typedef _Null_terminated_ CONST WCHAR UNALIGNED *LPCUWSTR, *PCUWSTR;

typedef _NullNull_terminated_ WCHAR *PZZWSTR;
typedef _NullNull_terminated_ CONST WCHAR *PCZZWSTR;
typedef _NullNull_terminated_ WCHAR UNALIGNED *PUZZWSTR;
typedef _NullNull_terminated_ CONST WCHAR UNALIGNED *PCUZZWSTR;

typedef  WCHAR *PNZWCH;
typedef  CONST WCHAR *PCNZWCH;
typedef  WCHAR UNALIGNED *PUNZWCH;
typedef  CONST WCHAR UNALIGNED *PCUNZWCH;

#if (_WIN32_WINNT >= 0x0600) || (defined(__cplusplus) && defined(WINDOWS_ENABLE_CPLUSPLUS))
 typedef CONST WCHAR *LPCWCHAR, *PCWCHAR;
 typedef CONST WCHAR UNALIGNED *LPCUWCHAR, *PCUWCHAR;
 typedef unsigned long UCSCHAR, *PUCSCHAR, *PUCSSTR;
 typedef const UCSCHAR *PCUCSCHAR, *PCUCSSTR;
 typedef UCSCHAR UNALIGNED *PUUCSCHAR, *PUUCSSTR;
 typedef const UCSCHAR UNALIGNED *PCUUCSCHAR, *PCUUCSSTR;
 #define UCSCHAR_INVALID_CHARACTER (0xffffffff)
 #define MIN_UCSCHAR (0)
 #define MAX_UCSCHAR (0x0010FFFF)
#endif /* _WIN32_WINNT >= 0x0600 */

#ifdef  UNICODE

 #ifndef _TCHAR_DEFINED
  typedef WCHAR TCHAR, *PTCHAR;
  typedef WCHAR TBYTE, *PTBYTE;
  #define _TCHAR_DEFINED
 #endif /* !_TCHAR_DEFINED */

 typedef LPWCH LPTCH, PTCH;
 typedef LPCWCH LPCTCH, PCTCH;
 typedef LPWSTR PTSTR, LPTSTR;
 typedef LPCWSTR PCTSTR, LPCTSTR;
 typedef LPUWSTR PUTSTR, LPUTSTR;
 typedef LPCUWSTR PCUTSTR, LPCUTSTR;
 typedef LPWSTR LP;
 typedef PZZWSTR PZZTSTR;
 typedef PCZZWSTR PCZZTSTR;
 typedef PUZZWSTR PUZZTSTR;
 typedef PCUZZWSTR PCUZZTSTR;
 typedef PZPWSTR PZPTSTR;
 typedef PNZWCH PNZTCH;
 typedef PCNZWCH PCNZTCH;
 typedef PUNZWCH PUNZTCH;
 typedef PCUNZWCH PCUNZTCH;
 #define __TEXT(quote) L##quote

#else /* UNICODE */

 #ifndef _TCHAR_DEFINED
  typedef char TCHAR, *PTCHAR;
  typedef unsigned char TBYTE, *PTBYTE;
  #define _TCHAR_DEFINED
 #endif /* !_TCHAR_DEFINED */
 typedef LPCH LPTCH, PTCH;
 typedef LPCCH LPCTCH, PCTCH;
 typedef LPSTR PTSTR, LPTSTR, PUTSTR, LPUTSTR;
 typedef LPCSTR PCTSTR, LPCTSTR, PCUTSTR, LPCUTSTR;
 typedef PZZSTR PZZTSTR, PUZZTSTR;
 typedef PCZZSTR PCZZTSTR, PCUZZTSTR;
 typedef PZPSTR PZPTSTR;
 typedef PNZCH PNZTCH, PUNZTCH;
 typedef PCNZCH PCNZTCH, PCUNZTCH;
 #define __TEXT(quote) quote

#endif /* UNICODE */

#define TEXT(quote) __TEXT(quote)

/* Cardinal Data Types */
typedef char CCHAR;

/* NLS basics (Locale and Language Ids) */
typedef DWORD LCID, *PLCID;
typedef WORD LANGID;

#ifndef __COMPARTMENT_ID_DEFINED__
#define __COMPARTMENT_ID_DEFINED__
typedef enum
{
    UNSPECIFIED_COMPARTMENT_ID = 0,
    DEFAULT_COMPARTMENT_ID
} COMPARTMENT_ID, *PCOMPARTMENT_ID;
#endif /* __COMPARTMENT_ID_DEFINED__ */

#ifndef __OBJECTID_DEFINED
#define __OBJECTID_DEFINED
typedef struct  _OBJECTID {
    GUID Lineage;
    DWORD Uniquifier;
} OBJECTID;
#endif /* __OBJECTID_DEFINED */

#ifdef _MSC_VER
 #pragma warning(push)
 #pragma warning(disable:4201) // nameless struct / union
#endif

typedef struct
#if defined(_M_IA64)
DECLSPEC_ALIGN(16)
#endif
_FLOAT128 {
    __int64 LowPart;
    __int64 HighPart;
} FLOAT128;
typedef FLOAT128 *PFLOAT128;

/* Large Integer Unions */
#if defined(MIDL_PASS)
typedef struct _LARGE_INTEGER {
#else
typedef union _LARGE_INTEGER {
    _ANONYMOUS_STRUCT struct
    {
        DWORD LowPart;
        LONG HighPart;
    } DUMMYSTRUCTNAME;
    struct
    {
        DWORD LowPart;
        LONG HighPart;
    } u;
#endif /* MIDL_PASS */
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

#if defined(MIDL_PASS)
typedef struct _ULARGE_INTEGER {
#else
typedef union _ULARGE_INTEGER {
    _ANONYMOUS_STRUCT struct
    {
        DWORD LowPart;
        DWORD HighPart;
    } DUMMYSTRUCTNAME;
    struct
    {
        DWORD LowPart;
        DWORD HighPart;
    } u;
#endif /* MIDL_PASS */
    ULONGLONG QuadPart;
} ULARGE_INTEGER, *PULARGE_INTEGER;

#ifdef _MSC_VER
#pragma warning(pop) /* disable:4201 */
#endif

/* Locally Unique Identifier */
typedef struct _LUID
{
    DWORD LowPart;
    LONG HighPart;
} LUID, *PLUID;

#define APPLICATION_ERROR_MASK       0x20000000
#define ERROR_SEVERITY_SUCCESS       0x00000000
#define ERROR_SEVERITY_INFORMATIONAL 0x40000000
#define ERROR_SEVERITY_WARNING       0x80000000
#define ERROR_SEVERITY_ERROR         0xC0000000


#define ANSI_NULL ((CHAR)0)
#define UNICODE_NULL ((WCHAR)0)
#define UNICODE_STRING_MAX_BYTES ((USHORT) 65534)
#define UNICODE_STRING_MAX_CHARS (32767)

/* Doubly Linked Lists */
typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY *Flink;
  struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;

typedef struct LIST_ENTRY32 {
  DWORD Flink;
  DWORD Blink;
} LIST_ENTRY32, *PLIST_ENTRY32;

typedef struct LIST_ENTRY64 {
  ULONGLONG Flink;
  ULONGLONG Blink;
} LIST_ENTRY64, *PLIST_ENTRY64;

/* Singly Linked Lists */
typedef struct _SINGLE_LIST_ENTRY {
  struct _SINGLE_LIST_ENTRY *Next;
} SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY;


typedef struct _PROCESSOR_NUMBER {
  WORD Group;
  BYTE Number;
  BYTE Reserved;
} PROCESSOR_NUMBER, *PPROCESSOR_NUMBER;

#define ALL_PROCESSOR_GROUPS 0xffff

typedef
_IRQL_requires_same_
_Function_class_(EXCEPTION_ROUTINE)
EXCEPTION_DISPOSITION
NTAPI
EXCEPTION_ROUTINE(
    _Inout_ struct _EXCEPTION_RECORD *ExceptionRecord,
    _In_ PVOID EstablisherFrame,
    _Inout_ struct _CONTEXT *ContextRecord,
    _In_ PVOID DispatcherContext);

typedef EXCEPTION_ROUTINE *PEXCEPTION_ROUTINE;

typedef struct _GROUP_AFFINITY {
  KAFFINITY Mask;
  WORD Group;
  WORD Reserved[3];
} GROUP_AFFINITY, *PGROUP_AFFINITY;

/* Helper Macros */

#define RTL_FIELD_TYPE(type, field)    (((type*)0)->field)
#define RTL_BITS_OF(sizeOfArg)         (sizeof(sizeOfArg) * 8)
#define RTL_BITS_OF_FIELD(type, field) (RTL_BITS_OF(RTL_FIELD_TYPE(type, field)))
#define RTL_FIELD_SIZE(type, field) (sizeof(((type *)0)->field))

#define RTL_SIZEOF_THROUGH_FIELD(type, field) \
    (FIELD_OFFSET(type, field) + RTL_FIELD_SIZE(type, field))

#define RTL_CONTAINS_FIELD(Struct, Size, Field) \
    ( (((PCHAR)(&(Struct)->Field)) + sizeof((Struct)->Field)) <= (((PCHAR)(Struct))+(Size)) )

#define RTL_NUMBER_OF_V1(A) (sizeof(A)/sizeof((A)[0]))

#ifdef __GNUC__
 #define RTL_NUMBER_OF_V2(A) \
     (({ int _check_array_type[__builtin_types_compatible_p(typeof(A), typeof(&A[0])) ? -1 : 1]; (void)_check_array_type; }), \
     RTL_NUMBER_OF_V1(A))
#elif defined(__cplusplus)
extern "C++" {
 template <typename T, size_t N>
 static char (& SAFE_RTL_NUMBER_OF(T (&)[N]))[N];
}
 #define RTL_NUMBER_OF_V2(A) sizeof(SAFE_RTL_NUMBER_OF(A))
#else
 #define RTL_NUMBER_OF_V2(A) RTL_NUMBER_OF_V1(A)
#endif

#ifdef ENABLE_RTL_NUMBER_OF_V2
 #define RTL_NUMBER_OF(A) RTL_NUMBER_OF_V2(A)
#else
 #define RTL_NUMBER_OF(A) RTL_NUMBER_OF_V1(A)
#endif

#define ARRAYSIZE(A)    RTL_NUMBER_OF_V2(A)
#define _ARRAYSIZE(A)   RTL_NUMBER_OF_V1(A)

#define RTL_NUMBER_OF_FIELD(type, field) \
    (RTL_NUMBER_OF(RTL_FIELD_TYPE(type, field)))

#define RTL_PADDING_BETWEEN_FIELDS(type, field1, field2) \
    ((FIELD_OFFSET(type, field2) > FIELD_OFFSET(type, field1)) \
        ? (FIELD_OFFSET(type, field2) - FIELD_OFFSET(type, field1) - RTL_FIELD_SIZE(type, field1)) \
        : (FIELD_OFFSET(type, field1) - FIELD_OFFSET(type, field2) - RTL_FIELD_SIZE(type, field2)))

#if defined(__cplusplus)
 #define RTL_CONST_CAST(type) const_cast<type>
#else
 #define RTL_CONST_CAST(type) (type)
#endif

#ifdef __cplusplus
#define DEFINE_ENUM_FLAG_OPERATORS(_ENUMTYPE) \
extern "C++" { \
  inline _ENUMTYPE operator|(_ENUMTYPE a, _ENUMTYPE b) { return _ENUMTYPE(((int)a) | ((int)b)); } \
  inline _ENUMTYPE &operator|=(_ENUMTYPE &a, _ENUMTYPE b) { return (_ENUMTYPE &)(((int &)a) |= ((int)b)); } \
  inline _ENUMTYPE operator&(_ENUMTYPE a, _ENUMTYPE b) { return _ENUMTYPE(((int)a) & ((int)b)); } \
  inline _ENUMTYPE &operator&=(_ENUMTYPE &a, _ENUMTYPE b) { return (_ENUMTYPE &)(((int &)a) &= ((int)b)); } \
  inline _ENUMTYPE operator~(_ENUMTYPE a) { return _ENUMTYPE(~((int)a)); } \
  inline _ENUMTYPE operator^(_ENUMTYPE a, _ENUMTYPE b) { return _ENUMTYPE(((int)a) ^ ((int)b)); } \
  inline _ENUMTYPE &operator^=(_ENUMTYPE &a, _ENUMTYPE b) { return (_ENUMTYPE &)(((int &)a) ^= ((int)b)); } \
}
#else
#define DEFINE_ENUM_FLAG_OPERATORS(_ENUMTYPE)
#endif

#define COMPILETIME_OR_2FLAGS(a,b)          ((UINT)(a)|(UINT)(b))
#define COMPILETIME_OR_3FLAGS(a,b,c)        ((UINT)(a)|(UINT)(b)|(UINT)(c))
#define COMPILETIME_OR_4FLAGS(a,b,c,d)      ((UINT)(a)|(UINT)(b)|(UINT)(c)|(UINT)(d))
#define COMPILETIME_OR_5FLAGS(a,b,c,d,e)    ((UINT)(a)|(UINT)(b)|(UINT)(c)|(UINT)(d)|(UINT)(e))

/* Type Limits */
#define MINCHAR   0x80
#define MAXCHAR   0x7f
#define MINSHORT  0x8000
#define MAXSHORT  0x7fff
#define MINLONG   0x80000000
#define MAXLONG   0x7fffffff
#define MAXBYTE   0xff
#define MAXWORD   0xffff
#define MAXDWORD  0xffffffff
#define MAXLONGLONG (0x7fffffffffffffffLL)

/* 32 to 64 bit multiplication. GCC is really bad at optimizing the native math */
#if defined(_M_IX86) && !defined(_M_ARM) && !defined(_M_ARM64) && \
    !defined(MIDL_PASS)&& !defined(RC_INVOKED) && !defined(_M_CEE_PURE)
 #define Int32x32To64(a,b) __emul(a,b)
 #define UInt32x32To64(a,b) __emulu(a,b)
#else
 #define Int32x32To64(a,b) (((__int64)(long)(a))*((__int64)(long)(b)))
 #define UInt32x32To64(a,b) ((unsigned __int64)(unsigned int)(a)*(unsigned __int64)(unsigned int)(b))
#endif

#if defined(MIDL_PASS)|| defined(RC_INVOKED) || defined(_M_CEE_PURE) || defined(_M_ARM)
/* Use native math */
 #define Int64ShllMod32(a,b) ((unsigned __int64)(a)<<(b))
 #define Int64ShraMod32(a,b) (((__int64)(a))>>(b))
 #define Int64ShrlMod32(a,b) (((unsigned __int64)(a))>>(b))
#else
/* Use intrinsics */
 #define Int64ShllMod32(a,b) __ll_lshift(a,b)
 #define Int64ShraMod32(a,b) __ll_rshift(a,b)
 #define Int64ShrlMod32(a,b) __ull_rshift(a,b)
#endif

#define RotateLeft32 _rotl
#define RotateLeft64 _rotl64
#define RotateRight32 _rotr
#define RotateRight64 _rotr64

#if defined(_M_AMD64)
 #define RotateLeft8 _rotl8
 #define RotateLeft16 _rotl16
 #define RotateRight8 _rotr8
 #define RotateRight16 _rotr16
#endif /* _M_AMD64 */

/* C_ASSERT Definition */
#define C_ASSERT(expr) extern char (*c_assert(void)) [(expr) ? 1 : -1]

/* Eliminate Microsoft C/C++ compiler warning 4715 */
#if defined(_MSC_VER)
 #define DEFAULT_UNREACHABLE default: __assume(0)
#elif defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 5))))
 #define DEFAULT_UNREACHABLE default: __builtin_unreachable()
#else
 #define DEFAULT_UNREACHABLE default: break
#endif

#if defined(__GNUC__) || defined(__clang__)
 #define UNREACHABLE __builtin_unreachable()
#elif defined(_MSC_VER)
 #define UNREACHABLE __assume(0)
#else
 #define UNREACHABLE
#endif

#define VER_WORKSTATION_NT                  0x40000000
#define VER_SERVER_NT                       0x80000000
#define VER_SUITE_SMALLBUSINESS             0x00000001
#define VER_SUITE_ENTERPRISE                0x00000002
#define VER_SUITE_BACKOFFICE                0x00000004
#define VER_SUITE_COMMUNICATIONS            0x00000008
#define VER_SUITE_TERMINAL                  0x00000010
#define VER_SUITE_SMALLBUSINESS_RESTRICTED  0x00000020
#define VER_SUITE_EMBEDDEDNT                0x00000040
#define VER_SUITE_DATACENTER                0x00000080
#define VER_SUITE_SINGLEUSERTS              0x00000100
#define VER_SUITE_PERSONAL                  0x00000200
#define VER_SUITE_BLADE                     0x00000400
#define VER_SUITE_EMBEDDED_RESTRICTED       0x00000800
#define VER_SUITE_SECURITY_APPLIANCE        0x00001000
#define VER_SUITE_STORAGE_SERVER            0x00002000
#define VER_SUITE_COMPUTE_SERVER            0x00004000
#define VER_SUITE_WH_SERVER                 0x00008000

/* Product types */
#define PRODUCT_UNDEFINED                           0x00000000
#define PRODUCT_ULTIMATE                            0x00000001
#define PRODUCT_HOME_BASIC                          0x00000002
#define PRODUCT_HOME_PREMIUM                        0x00000003
#define PRODUCT_ENTERPRISE                          0x00000004
#define PRODUCT_HOME_BASIC_N                        0x00000005
#define PRODUCT_BUSINESS                            0x00000006
#define PRODUCT_STANDARD_SERVER                     0x00000007
#define PRODUCT_DATACENTER_SERVER                   0x00000008
#define PRODUCT_SMALLBUSINESS_SERVER                0x00000009
#define PRODUCT_ENTERPRISE_SERVER                   0x0000000A
#define PRODUCT_STARTER                             0x0000000B
#define PRODUCT_DATACENTER_SERVER_CORE              0x0000000C
#define PRODUCT_STANDARD_SERVER_CORE                0x0000000D
#define PRODUCT_ENTERPRISE_SERVER_CORE              0x0000000E
#define PRODUCT_ENTERPRISE_SERVER_IA64              0x0000000F
#define PRODUCT_BUSINESS_N                          0x00000010
#define PRODUCT_WEB_SERVER                          0x00000011
#define PRODUCT_CLUSTER_SERVER                      0x00000012
#define PRODUCT_HOME_SERVER                         0x00000013
#define PRODUCT_STORAGE_EXPRESS_SERVER              0x00000014
#define PRODUCT_STORAGE_STANDARD_SERVER             0x00000015
#define PRODUCT_STORAGE_WORKGROUP_SERVER            0x00000016
#define PRODUCT_STORAGE_ENTERPRISE_SERVER           0x00000017
#define PRODUCT_SERVER_FOR_SMALLBUSINESS            0x00000018
#define PRODUCT_SMALLBUSINESS_SERVER_PREMIUM        0x00000019
#define PRODUCT_HOME_PREMIUM_N                      0x0000001A
#define PRODUCT_ENTERPRISE_N                        0x0000001B
#define PRODUCT_ULTIMATE_N                          0x0000001C
#define PRODUCT_WEB_SERVER_CORE                     0x0000001D
#define PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT    0x0000001E
#define PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY      0x0000001F
#define PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING     0x00000020
#define PRODUCT_SERVER_FOUNDATION                   0x00000021
#define PRODUCT_HOME_PREMIUM_SERVER                 0x00000022
#define PRODUCT_SERVER_FOR_SMALLBUSINESS_V          0x00000023
#define PRODUCT_STANDARD_SERVER_V                   0x00000024
#define PRODUCT_DATACENTER_SERVER_V                 0x00000025
#define PRODUCT_ENTERPRISE_SERVER_V                 0x00000026
#define PRODUCT_DATACENTER_SERVER_CORE_V            0x00000027
#define PRODUCT_STANDARD_SERVER_CORE_V              0x00000028
#define PRODUCT_ENTERPRISE_SERVER_CORE_V            0x00000029
#define PRODUCT_HYPERV                              0x0000002A
#define PRODUCT_STORAGE_EXPRESS_SERVER_CORE         0x0000002B
#define PRODUCT_STORAGE_STANDARD_SERVER_CORE        0x0000002C
#define PRODUCT_STORAGE_WORKGROUP_SERVER_CORE       0x0000002D
#define PRODUCT_STORAGE_ENTERPRISE_SERVER_CORE      0x0000002E
#define PRODUCT_STARTER_N                           0x0000002F
#define PRODUCT_PROFESSIONAL                        0x00000030
#define PRODUCT_PROFESSIONAL_N                      0x00000031
#define PRODUCT_SB_SOLUTION_SERVER                  0x00000032
#define PRODUCT_SERVER_FOR_SB_SOLUTIONS             0x00000033
#define PRODUCT_STANDARD_SERVER_SOLUTIONS           0x00000034
#define PRODUCT_STANDARD_SERVER_SOLUTIONS_CORE      0x00000035
#define PRODUCT_SB_SOLUTION_SERVER_EM               0x00000036
#define PRODUCT_SERVER_FOR_SB_SOLUTIONS_EM          0x00000037
#define PRODUCT_SOLUTION_EMBEDDEDSERVER             0x00000038
#define PRODUCT_SOLUTION_EMBEDDEDSERVER_CORE        0x00000039
#define PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT       0x0000003B
#define PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL       0x0000003C
#define PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC    0x0000003D
#define PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC    0x0000003E
#define PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_CORE   0x0000003F
#define PRODUCT_CLUSTER_SERVER_V                    0x00000040
#define PRODUCT_EMBEDDED                            0x00000041
#define PRODUCT_STARTER_E                           0x00000042
#define PRODUCT_HOME_BASIC_E                        0x00000043
#define PRODUCT_HOME_PREMIUM_E                      0x00000044
#define PRODUCT_PROFESSIONAL_E                      0x00000045
#define PRODUCT_ENTERPRISE_E                        0x00000046
#define PRODUCT_ULTIMATE_E                          0x00000047
#define PRODUCT_ENTERPRISE_EVALUATION               0x00000048
#define PRODUCT_MULTIPOINT_STANDARD_SERVER          0x0000004C
#define PRODUCT_MULTIPOINT_PREMIUM_SERVER           0x0000004D
#define PRODUCT_STANDARD_EVALUATION_SERVER          0x0000004F
#define PRODUCT_DATACENTER_EVALUATION_SERVER        0x00000050
#define PRODUCT_ENTERPRISE_N_EVALUATION             0x00000054
#define PRODUCT_EMBEDDED_AUTOMOTIVE                 0x00000055
#define PRODUCT_EMBEDDED_INDUSTRY_A                 0x00000056
#define PRODUCT_THINPC                              0x00000057
#define PRODUCT_EMBEDDED_A                          0x00000058
#define PRODUCT_EMBEDDED_INDUSTRY                   0x00000059
#define PRODUCT_EMBEDDED_E                          0x0000005A
#define PRODUCT_EMBEDDED_INDUSTRY_E                 0x0000005B
#define PRODUCT_EMBEDDED_INDUSTRY_A_E               0x0000005C
#define PRODUCT_STORAGE_WORKGROUP_EVALUATION_SERVER 0x0000005F
#define PRODUCT_STORAGE_STANDARD_EVALUATION_SERVER  0x00000060
#define PRODUCT_CORE_ARM                            0x00000061
#define PRODUCT_CORE_N                              0x00000062
#define PRODUCT_CORE_COUNTRYSPECIFIC                0x00000063
#define PRODUCT_CORE_SINGLELANGUAGE                 0x00000064
#define PRODUCT_CORE                                0x00000065
#define PRODUCT_PROFESSIONAL_WMC                    0x00000067
#define PRODUCT_ENTERPRISE_S_N_EVALUATION           0x00000082
#define PRODUCT_UNLICENSED                          0xABCDABCD

/* LangID and NLS */
#define MAKELANGID(p, s)       ((((USHORT)(s)) << 10) | (USHORT)(p))
#define PRIMARYLANGID(lgid)    ((USHORT)(lgid) & 0x3ff)
#define SUBLANGID(lgid)        ((USHORT)(lgid) >> 10)
#define MAKELCID(lgid, srtid)  ((DWORD)((((DWORD)((USHORT)(srtid))) << 16) |  \
                                          ((DWORD)((USHORT)(lgid)))))
#define MAKESORTLCID(lgid, srtid, ver)                                        \
                               ((DWORD)((MAKELCID(lgid, srtid)) |             \
                                    (((DWORD)((USHORT)(ver))) << 20)))
#define LANGIDFROMLCID(lcid)   ((USHORT)(lcid))
#define SORTIDFROMLCID(lcid)   ((USHORT)((((DWORD)(lcid)) >> 16) & 0xf))
#define SORTVERSIONFROMLCID(lcid)  ((USHORT)((((DWORD)(lcid)) >> 20) & 0xf))

#define NLS_VALID_LOCALE_MASK  0x000fffff
#define LOCALE_NAME_MAX_LENGTH   85

/*  Primary language IDs. */
#define LANG_NEUTRAL                              0x00
#define LANG_INVARIANT                            0x7f
#define LANG_AFRIKAANS                            0x36
#define LANG_ALBANIAN                             0x1c
#define LANG_ALSATIAN                             0x84
#define LANG_AMHARIC                              0x5e
#define LANG_ARABIC                               0x01
#define LANG_ARMENIAN                             0x2b
#define LANG_ASSAMESE                             0x4d
#define LANG_AZERI                                0x2c
#define LANG_AZERBAIJANI                          0x2c
#define LANG_BANGLA                               0x45
#define LANG_BASHKIR                              0x6d
#define LANG_BASQUE                               0x2d
#define LANG_BELARUSIAN                           0x23
#define LANG_BENGALI                              0x45
#define LANG_BOSNIAN                              0x1a
#define LANG_BOSNIAN_NEUTRAL                    0x781a
#define LANG_BRETON                               0x7e
#define LANG_BULGARIAN                            0x02
#define LANG_CATALAN                              0x03
#define LANG_CENTRAL_KURDISH                      0x92
#define LANG_CHEROKEE                             0x5c
#define LANG_CHINESE                              0x04
#define LANG_CHINESE_SIMPLIFIED                   0x04
#define LANG_CHINESE_TRADITIONAL                0x7c04
#define LANG_CORSICAN                             0x83
#define LANG_CROATIAN                             0x1a
#define LANG_CZECH                                0x05
#define LANG_DANISH                               0x06
#define LANG_DARI                                 0x8c
#define LANG_DIVEHI                               0x65
#define LANG_DUTCH                                0x13
#define LANG_ENGLISH                              0x09
#define LANG_ESTONIAN                             0x25
#define LANG_FAEROESE                             0x38
#define LANG_FARSI                                0x29
#define LANG_FILIPINO                             0x64
#define LANG_FINNISH                              0x0b
#define LANG_FRENCH                               0x0c
#define LANG_FRISIAN                              0x62
#define LANG_FULAH                                0x67
#define LANG_GALICIAN                             0x56
#define LANG_GEORGIAN                             0x37
#define LANG_GERMAN                               0x07
#define LANG_GREEK                                0x08
#define LANG_GREENLANDIC                          0x6f
#define LANG_GUJARATI                             0x47
#define LANG_HAUSA                                0x68
#define LANG_HAWAIIAN                             0x75
#define LANG_HEBREW                               0x0d
#define LANG_HINDI                                0x39
#define LANG_HUNGARIAN                            0x0e
#define LANG_ICELANDIC                            0x0f
#define LANG_IGBO                                 0x70
#define LANG_INDONESIAN                           0x21
#define LANG_INUKTITUT                            0x5d
#define LANG_IRISH                                0x3c
#define LANG_ITALIAN                              0x10
#define LANG_JAPANESE                             0x11
#define LANG_KANNADA                              0x4b
#define LANG_KASHMIRI                             0x60
#define LANG_KAZAK                                0x3f
#define LANG_KHMER                                0x53
#define LANG_KICHE                                0x86
#define LANG_KINYARWANDA                          0x87
#define LANG_KONKANI                              0x57
#define LANG_KOREAN                               0x12
#define LANG_KYRGYZ                               0x40
#define LANG_LAO                                  0x54
#define LANG_LATVIAN                              0x26
#define LANG_LITHUANIAN                           0x27
#define LANG_LOWER_SORBIAN                        0x2e
#define LANG_LUXEMBOURGISH                        0x6e
#define LANG_MACEDONIAN                           0x2f
#define LANG_MALAY                                0x3e
#define LANG_MALAYALAM                            0x4c
#define LANG_MALTESE                              0x3a
#define LANG_MANIPURI                             0x58
#define LANG_MAORI                                0x81
#define LANG_MAPUDUNGUN                           0x7a
#define LANG_MARATHI                              0x4e
#define LANG_MOHAWK                               0x7c
#define LANG_MONGOLIAN                            0x50
#define LANG_NEPALI                               0x61
#define LANG_NORWEGIAN                            0x14
#define LANG_OCCITAN                              0x82
#define LANG_ODIA                                 0x48
#define LANG_ORIYA                                0x48
#define LANG_PASHTO                               0x63
#define LANG_PERSIAN                              0x29
#define LANG_POLISH                               0x15
#define LANG_PORTUGUESE                           0x16
#define LANG_PULAR                                0x67
#define LANG_PUNJABI                              0x46
#define LANG_QUECHUA                              0x6b
#define LANG_ROMANIAN                             0x18
#define LANG_ROMANSH                              0x17
#define LANG_RUSSIAN                              0x19
#define LANG_SAKHA                                0x85
#define LANG_SAMI                                 0x3b
#define LANG_SANSKRIT                             0x4f
#define LANG_SCOTTISH_GAELIC                      0x91
#define LANG_SERBIAN                              0x1a
#define LANG_SERBIAN_NEUTRAL                    0x7c1a
#define LANG_SINDHI                               0x59
#define LANG_SINHALESE                            0x5b
#define LANG_SLOVAK                               0x1b
#define LANG_SLOVENIAN                            0x24
#define LANG_SOTHO                                0x6c
#define LANG_SPANISH                              0x0a
#define LANG_SWAHILI                              0x41
#define LANG_SWEDISH                              0x1d
#define LANG_SYRIAC                               0x5a
#define LANG_TAJIK                                0x28
#define LANG_TAMAZIGHT                            0x5f
#define LANG_TAMIL                                0x49
#define LANG_TATAR                                0x44
#define LANG_TELUGU                               0x4a
#define LANG_THAI                                 0x1e
#define LANG_TIBETAN                              0x51
#define LANG_TIGRIGNA                             0x73
#define LANG_TIGRINYA                             0x73
#define LANG_TSWANA                               0x32
#define LANG_TURKISH                              0x1f
#define LANG_TURKMEN                              0x42
#define LANG_UIGHUR                               0x80
#define LANG_UKRAINIAN                            0x22
#define LANG_UPPER_SORBIAN                        0x2e
#define LANG_URDU                                 0x20
#define LANG_UZBEK                                0x43
#define LANG_VALENCIAN                            0x03
#define LANG_VIETNAMESE                           0x2a
#define LANG_WELSH                                0x52
#define LANG_WOLOF                                0x88
#define LANG_XHOSA                                0x34
#define LANG_YAKUT                                0x85
#define LANG_YI                                   0x78
#define LANG_YORUBA                               0x6a
#define LANG_ZULU                                 0x35

#ifdef __REACTOS__
/* WINE extensions */
/* These are documented by the MSDN but are missing from the Windows header */
#define LANG_MALAGASY       0x8d

/* FIXME: these are not defined anywhere */
#define LANG_SUTU           0x30
#define LANG_TSONGA         0x31
#define LANG_VENDA          0x33

/* non standard; keep the number high enough (but < 0xff) */
#define LANG_ASTURIAN                    0xa5
#define LANG_ESPERANTO                   0x8f
#define LANG_WALON                       0x90
#define LANG_CORNISH                     0x92
#define LANG_MANX_GAELIC                 0x94
#endif

#define SUBLANG_NEUTRAL                             0x00
#define SUBLANG_DEFAULT                             0x01
#define SUBLANG_SYS_DEFAULT                         0x02
#define SUBLANG_CUSTOM_DEFAULT                      0x03
#define SUBLANG_CUSTOM_UNSPECIFIED                  0x04
#define SUBLANG_UI_CUSTOM_DEFAULT                   0x05
#define SUBLANG_AFRIKAANS_SOUTH_AFRICA              0x01
#define SUBLANG_ALBANIAN_ALBANIA                    0x01
#define SUBLANG_ALSATIAN_FRANCE                     0x01
#define SUBLANG_AMHARIC_ETHIOPIA                    0x01
#define SUBLANG_ARABIC_SAUDI_ARABIA                 0x01
#define SUBLANG_ARABIC_IRAQ                         0x02
#define SUBLANG_ARABIC_EGYPT                        0x03
#define SUBLANG_ARABIC_LIBYA                        0x04
#define SUBLANG_ARABIC_ALGERIA                      0x05
#define SUBLANG_ARABIC_MOROCCO                      0x06
#define SUBLANG_ARABIC_TUNISIA                      0x07
#define SUBLANG_ARABIC_OMAN                         0x08
#define SUBLANG_ARABIC_YEMEN                        0x09
#define SUBLANG_ARABIC_SYRIA                        0x0a
#define SUBLANG_ARABIC_JORDAN                       0x0b
#define SUBLANG_ARABIC_LEBANON                      0x0c
#define SUBLANG_ARABIC_KUWAIT                       0x0d
#define SUBLANG_ARABIC_UAE                          0x0e
#define SUBLANG_ARABIC_BAHRAIN                      0x0f
#define SUBLANG_ARABIC_QATAR                        0x10
#define SUBLANG_ARMENIAN_ARMENIA                    0x01
#define SUBLANG_ASSAMESE_INDIA                      0x01
#define SUBLANG_AZERI_LATIN                         0x01
#define SUBLANG_AZERI_CYRILLIC                      0x02
#define SUBLANG_AZERBAIJANI_AZERBAIJAN_LATIN        0x01
#define SUBLANG_AZERBAIJANI_AZERBAIJAN_CYRILLIC     0x02
#define SUBLANG_BANGLA_INDIA                        0x01
#define SUBLANG_BANGLA_BANGLADESH                   0x02
#define SUBLANG_BASHKIR_RUSSIA                      0x01
#define SUBLANG_BASQUE_BASQUE                       0x01
#define SUBLANG_BELARUSIAN_BELARUS                  0x01
#define SUBLANG_BENGALI_INDIA                       0x01
#define SUBLANG_BENGALI_BANGLADESH                  0x02
#define SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_LATIN    0x05
#define SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_CYRILLIC 0x08
#define SUBLANG_BRETON_FRANCE                       0x01
#define SUBLANG_BULGARIAN_BULGARIA                  0x01
#define SUBLANG_CATALAN_CATALAN                     0x01
#define SUBLANG_CENTRAL_KURDISH_IRAQ                0x01
#define SUBLANG_CHEROKEE_CHEROKEE                   0x01
#define SUBLANG_CHINESE_TRADITIONAL                 0x01
#define SUBLANG_CHINESE_SIMPLIFIED                  0x02
#define SUBLANG_CHINESE_HONGKONG                    0x03
#define SUBLANG_CHINESE_SINGAPORE                   0x04
#define SUBLANG_CHINESE_MACAU                       0x05
#define SUBLANG_CORSICAN_FRANCE                     0x01
#define SUBLANG_CZECH_CZECH_REPUBLIC                0x01
#define SUBLANG_CROATIAN_CROATIA                    0x01
#define SUBLANG_CROATIAN_BOSNIA_HERZEGOVINA_LATIN   0x04
#define SUBLANG_DANISH_DENMARK                      0x01
#define SUBLANG_DARI_AFGHANISTAN                    0x01
#define SUBLANG_DIVEHI_MALDIVES                     0x01
#define SUBLANG_DUTCH                               0x01
#define SUBLANG_DUTCH_BELGIAN                       0x02
#define SUBLANG_ENGLISH_US                          0x01
#define SUBLANG_ENGLISH_UK                          0x02
#define SUBLANG_ENGLISH_AUS                         0x03
#define SUBLANG_ENGLISH_CAN                         0x04
#define SUBLANG_ENGLISH_NZ                          0x05
#define SUBLANG_ENGLISH_EIRE                        0x06
#define SUBLANG_ENGLISH_SOUTH_AFRICA                0x07
#define SUBLANG_ENGLISH_JAMAICA                     0x08
#define SUBLANG_ENGLISH_CARIBBEAN                   0x09
#define SUBLANG_ENGLISH_BELIZE                      0x0a
#define SUBLANG_ENGLISH_TRINIDAD                    0x0b
#define SUBLANG_ENGLISH_ZIMBABWE                    0x0c
#define SUBLANG_ENGLISH_PHILIPPINES                 0x0d
#define SUBLANG_ENGLISH_INDIA                       0x10
#define SUBLANG_ENGLISH_MALAYSIA                    0x11
#define SUBLANG_ENGLISH_SINGAPORE                   0x12
#define SUBLANG_ESTONIAN_ESTONIA                    0x01
#define SUBLANG_FAEROESE_FAROE_ISLANDS              0x01
#define SUBLANG_FILIPINO_PHILIPPINES                0x01
#define SUBLANG_FINNISH_FINLAND                     0x01
#define SUBLANG_FRENCH                              0x01
#define SUBLANG_FRENCH_BELGIAN                      0x02
#define SUBLANG_FRENCH_CANADIAN                     0x03
#define SUBLANG_FRENCH_SWISS                        0x04
#define SUBLANG_FRENCH_LUXEMBOURG                   0x05
#define SUBLANG_FRENCH_MONACO                       0x06
#define SUBLANG_FRISIAN_NETHERLANDS                 0x01
#define SUBLANG_FULAH_SENEGAL                       0x02
#define SUBLANG_GALICIAN_GALICIAN                   0x01
#define SUBLANG_GEORGIAN_GEORGIA                    0x01
#define SUBLANG_GERMAN                              0x01
#define SUBLANG_GERMAN_SWISS                        0x02
#define SUBLANG_GERMAN_AUSTRIAN                     0x03
#define SUBLANG_GERMAN_LUXEMBOURG                   0x04
#define SUBLANG_GERMAN_LIECHTENSTEIN                0x05
#define SUBLANG_GREEK_GREECE                        0x01
#define SUBLANG_GREENLANDIC_GREENLAND               0x01
#define SUBLANG_GUJARATI_INDIA                      0x01
#define SUBLANG_HAUSA_NIGERIA_LATIN                 0x01
#define SUBLANG_HAWAIIAN_US                         0x01
#define SUBLANG_HEBREW_ISRAEL                       0x01
#define SUBLANG_HINDI_INDIA                         0x01
#define SUBLANG_HUNGARIAN_HUNGARY                   0x01
#define SUBLANG_ICELANDIC_ICELAND                   0x01
#define SUBLANG_IGBO_NIGERIA                        0x01
#define SUBLANG_INDONESIAN_INDONESIA                0x01
#define SUBLANG_INUKTITUT_CANADA                    0x01
#define SUBLANG_INUKTITUT_CANADA_LATIN              0x02
#define SUBLANG_IRISH_IRELAND                       0x02
#define SUBLANG_ITALIAN                             0x01
#define SUBLANG_ITALIAN_SWISS                       0x02
#define SUBLANG_JAPANESE_JAPAN                      0x01
#define SUBLANG_KANNADA_INDIA                       0x01
#define SUBLANG_KASHMIRI_SASIA                      0x02
#define SUBLANG_KASHMIRI_INDIA                      0x02
#define SUBLANG_KAZAK_KAZAKHSTAN                    0x01
#define SUBLANG_KHMER_CAMBODIA                      0x01
#define SUBLANG_KICHE_GUATEMALA                     0x01
#define SUBLANG_KINYARWANDA_RWANDA                  0x01
#define SUBLANG_KONKANI_INDIA                       0x01
#define SUBLANG_KOREAN                              0x01
#define SUBLANG_KYRGYZ_KYRGYZSTAN                   0x01
#define SUBLANG_LAO_LAO                             0x01
#define SUBLANG_LATVIAN_LATVIA                      0x01
#define SUBLANG_LITHUANIAN                          0x01
#define SUBLANG_LOWER_SORBIAN_GERMANY               0x02
#define SUBLANG_LUXEMBOURGISH_LUXEMBOURG            0x01
#define SUBLANG_MACEDONIAN_MACEDONIA                0x01
#define SUBLANG_MALAY_MALAYSIA                      0x01
#define SUBLANG_MALAY_BRUNEI_DARUSSALAM             0x02
#define SUBLANG_MALAYALAM_INDIA                     0x01
#define SUBLANG_MALTESE_MALTA                       0x01
#define SUBLANG_MAORI_NEW_ZEALAND                   0x01
#define SUBLANG_MAPUDUNGUN_CHILE                    0x01
#define SUBLANG_MARATHI_INDIA                       0x01
#define SUBLANG_MOHAWK_MOHAWK                       0x01
#define SUBLANG_MONGOLIAN_CYRILLIC_MONGOLIA         0x01
#define SUBLANG_MONGOLIAN_PRC                       0x02
#define SUBLANG_NEPALI_INDIA                        0x02
#define SUBLANG_NEPALI_NEPAL                        0x01
#define SUBLANG_NORWEGIAN_BOKMAL                    0x01
#define SUBLANG_NORWEGIAN_NYNORSK                   0x02
#define SUBLANG_OCCITAN_FRANCE                      0x01
#define SUBLANG_ODIA_INDIA                          0x01
#define SUBLANG_ORIYA_INDIA                         0x01
#define SUBLANG_PASHTO_AFGHANISTAN                  0x01
#define SUBLANG_PERSIAN_IRAN                        0x01
#define SUBLANG_POLISH_POLAND                       0x01
#define SUBLANG_PORTUGUESE                          0x02
#define SUBLANG_PORTUGUESE_BRAZILIAN                0x01
#define SUBLANG_PULAR_SENEGAL                       0x02
#define SUBLANG_PUNJABI_INDIA                       0x01
#define SUBLANG_PUNJABI_PAKISTAN                    0x02
#define SUBLANG_QUECHUA_BOLIVIA                     0x01
#define SUBLANG_QUECHUA_ECUADOR                     0x02
#define SUBLANG_QUECHUA_PERU                        0x03
#define SUBLANG_ROMANIAN_ROMANIA                    0x01
#define SUBLANG_ROMANSH_SWITZERLAND                 0x01
#define SUBLANG_RUSSIAN_RUSSIA                      0x01
#define SUBLANG_SAKHA_RUSSIA                        0x01
#define SUBLANG_SAMI_NORTHERN_NORWAY                0x01
#define SUBLANG_SAMI_NORTHERN_SWEDEN                0x02
#define SUBLANG_SAMI_NORTHERN_FINLAND               0x03
#define SUBLANG_SAMI_LULE_NORWAY                    0x04
#define SUBLANG_SAMI_LULE_SWEDEN                    0x05
#define SUBLANG_SAMI_SOUTHERN_NORWAY                0x06
#define SUBLANG_SAMI_SOUTHERN_SWEDEN                0x07
#define SUBLANG_SAMI_SKOLT_FINLAND                  0x08
#define SUBLANG_SAMI_INARI_FINLAND                  0x09
#define SUBLANG_SANSKRIT_INDIA                      0x01
#define SUBLANG_SCOTTISH_GAELIC                     0x01
#define SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_LATIN    0x06
#define SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_CYRILLIC 0x07
#define SUBLANG_SERBIAN_MONTENEGRO_LATIN            0x0b
#define SUBLANG_SERBIAN_MONTENEGRO_CYRILLIC         0x0c
#define SUBLANG_SERBIAN_SERBIA_LATIN                0x09
#define SUBLANG_SERBIAN_SERBIA_CYRILLIC             0x0a
#define SUBLANG_SERBIAN_CROATIA                     0x01
#define SUBLANG_SERBIAN_LATIN                       0x02
#define SUBLANG_SERBIAN_CYRILLIC                    0x03
#define SUBLANG_SINDHI_INDIA                        0x01
#define SUBLANG_SINDHI_PAKISTAN                     0x02
#define SUBLANG_SINDHI_AFGHANISTAN                  0x02
#define SUBLANG_SINHALESE_SRI_LANKA                 0x01
#define SUBLANG_SOTHO_NORTHERN_SOUTH_AFRICA         0x01
#define SUBLANG_SLOVAK_SLOVAKIA                     0x01
#define SUBLANG_SLOVENIAN_SLOVENIA                  0x01
#define SUBLANG_SPANISH                             0x01
#define SUBLANG_SPANISH_MEXICAN                     0x02
#define SUBLANG_SPANISH_MODERN                      0x03
#define SUBLANG_SPANISH_GUATEMALA                   0x04
#define SUBLANG_SPANISH_COSTA_RICA                  0x05
#define SUBLANG_SPANISH_PANAMA                      0x06
#define SUBLANG_SPANISH_DOMINICAN_REPUBLIC          0x07
#define SUBLANG_SPANISH_VENEZUELA                   0x08
#define SUBLANG_SPANISH_COLOMBIA                    0x09
#define SUBLANG_SPANISH_PERU                        0x0a
#define SUBLANG_SPANISH_ARGENTINA                   0x0b
#define SUBLANG_SPANISH_ECUADOR                     0x0c
#define SUBLANG_SPANISH_CHILE                       0x0d
#define SUBLANG_SPANISH_URUGUAY                     0x0e
#define SUBLANG_SPANISH_PARAGUAY                    0x0f
#define SUBLANG_SPANISH_BOLIVIA                     0x10
#define SUBLANG_SPANISH_EL_SALVADOR                 0x11
#define SUBLANG_SPANISH_HONDURAS                    0x12
#define SUBLANG_SPANISH_NICARAGUA                   0x13
#define SUBLANG_SPANISH_PUERTO_RICO                 0x14
#define SUBLANG_SPANISH_US                          0x15
#define SUBLANG_SWAHILI_KENYA                       0x01
#define SUBLANG_SWEDISH                             0x01
#define SUBLANG_SWEDISH_FINLAND                     0x02
#define SUBLANG_SYRIAC_SYRIA                        0x01
#define SUBLANG_TAJIK_TAJIKISTAN                    0x01
#define SUBLANG_TAMAZIGHT_ALGERIA_LATIN             0x02
#define SUBLANG_TAMAZIGHT_MOROCCO_TIFINAGH          0x04
#define SUBLANG_TAMIL_INDIA                         0x01
#define SUBLANG_TAMIL_SRI_LANKA                     0x02
#define SUBLANG_TATAR_RUSSIA                        0x01
#define SUBLANG_TELUGU_INDIA                        0x01
#define SUBLANG_THAI_THAILAND                       0x01
#define SUBLANG_TIBETAN_PRC                         0x01
#define SUBLANG_TIGRIGNA_ERITREA                    0x02
#define SUBLANG_TIGRINYA_ERITREA                    0x02
#define SUBLANG_TIGRINYA_ETHIOPIA                   0x01
#define SUBLANG_TSWANA_BOTSWANA                     0x02
#define SUBLANG_TSWANA_SOUTH_AFRICA                 0x01
#define SUBLANG_TURKISH_TURKEY                      0x01
#define SUBLANG_TURKMEN_TURKMENISTAN                0x01
#define SUBLANG_UIGHUR_PRC                          0x01
#define SUBLANG_UKRAINIAN_UKRAINE                   0x01
#define SUBLANG_UPPER_SORBIAN_GERMANY               0x01
#define SUBLANG_URDU_PAKISTAN                       0x01
#define SUBLANG_URDU_INDIA                          0x02
#define SUBLANG_UZBEK_LATIN                         0x01
#define SUBLANG_UZBEK_CYRILLIC                      0x02
#define SUBLANG_VALENCIAN_VALENCIA                  0x02
#define SUBLANG_VIETNAMESE_VIETNAM                  0x01
#define SUBLANG_WELSH_UNITED_KINGDOM                0x01
#define SUBLANG_WOLOF_SENEGAL                       0x01
#define SUBLANG_XHOSA_SOUTH_AFRICA                  0x01
#define SUBLANG_YAKUT_RUSSIA                        0x01
#define SUBLANG_YI_PRC                              0x01
#define SUBLANG_YORUBA_NIGERIA                      0x01
#define SUBLANG_ZULU_SOUTH_AFRICA                   0x01

#ifdef __REACTOS__
/* WINE extensions */
#define SUBLANG_DUTCH_SURINAM              0x03
#define SUBLANG_ROMANIAN_MOLDAVIA          0x02
#define SUBLANG_RUSSIAN_MOLDAVIA           0x02
#define SUBLANG_LITHUANIAN_CLASSIC         0x02
#define SUBLANG_MANX_GAELIC                0x01
#endif

#define SORT_DEFAULT                     0x0
#define SORT_INVARIANT_MATH              0x1
#define SORT_JAPANESE_XJIS               0x0
#define SORT_JAPANESE_UNICODE            0x1
#define SORT_JAPANESE_RADICALSTROKE      0x4
#define SORT_CHINESE_BIG5                0x0
#define SORT_CHINESE_PRCP                0x0
#define SORT_CHINESE_UNICODE             0x1
#define SORT_CHINESE_PRC                 0x2
#define SORT_CHINESE_BOPOMOFO            0x3
#define SORT_CHINESE_RADICALSTROKE       0x4
#define SORT_KOREAN_KSC                  0x0
#define SORT_KOREAN_UNICODE              0x1
#define SORT_GERMAN_PHONE_BOOK           0x1
#define SORT_HUNGARIAN_DEFAULT           0x0
#define SORT_HUNGARIAN_TECHNICAL         0x1
#define SORT_GEORGIAN_TRADITIONAL        0x0
#define SORT_GEORGIAN_MODERN             0x1

#define LANG_SYSTEM_DEFAULT       MAKELANGID(LANG_NEUTRAL, SUBLANG_SYS_DEFAULT)
#define LANG_USER_DEFAULT         MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)

#define LOCALE_SYSTEM_DEFAULT     MAKELCID(LANG_SYSTEM_DEFAULT, SORT_DEFAULT)
#define LOCALE_USER_DEFAULT       MAKELCID(LANG_USER_DEFAULT, SORT_DEFAULT)
#define LOCALE_CUSTOM_DEFAULT     MAKELCID(MAKELANGID(LANG_NEUTRAL, SUBLANG_CUSTOM_DEFAULT), SORT_DEFAULT)
#define LOCALE_CUSTOM_UNSPECIFIED MAKELCID(MAKELANGID(LANG_NEUTRAL, SUBLANG_CUSTOM_UNSPECIFIED), SORT_DEFAULT)
#define LOCALE_CUSTOM_UI_DEFAULT  MAKELCID(MAKELANGID(LANG_NEUTRAL, SUBLANG_UI_CUSTOM_DEFAULT), SORT_DEFAULT)
#define LOCALE_NEUTRAL            MAKELCID(MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), SORT_DEFAULT)
#define LOCALE_INVARIANT          MAKELCID(MAKELANGID(LANG_INVARIANT, SUBLANG_NEUTRAL), SORT_DEFAULT)
/******************************************************************************
 *                           INTERLOCKED Functions                            *
 ******************************************************************************/

#define BitScanForward _BitScanForward
#define BitScanReverse _BitScanReverse
#define BitTest _bittest
#define BitTestAndComplement _bittestandcomplement
#define BitTestAndSet _bittestandset
#define BitTestAndReset _bittestandreset
#ifdef _WIN64
#define BitScanForward64 _BitScanForward64
#define BitScanReverse64 _BitScanReverse64
#define BitTest64 _bittest64
#define BitTestAndComplement64 _bittestandcomplement64
#define BitTestAndSet64 _bittestandset64
#define BitTestAndReset64 _bittestandreset64
#endif /* _WIN64 */

#if defined(_M_ARM) || defined(_M_IA64)
#define __ACQ_(x) x##_acq
#define __REL_(x) x##_rel
#define __NF_(x) x##_nf
#else
#define __ACQ_(x) x
#define __REL_(x) x
#define __NF_(x) x
#endif

#define InterlockedBitTestAndSet _interlockedbittestandset
#define InterlockedBitTestAndSetAcquire __ACQ_(_interlockedbittestandset)
#define InterlockedBitTestAndSetRelease __REL_(_interlockedbittestandset)
#define InterlockedBitTestAndSetNoFence __NF_(_interlockedbittestandset)

#define InterlockedBitTestAndReset _interlockedbittestandreset
#define InterlockedBitTestAndResetAcquire __ACQ_(_interlockedbittestandreset)
#define InterlockedBitTestAndResetRelease __REL_(_interlockedbittestandreset)
#define InterlockedBitTestAndResetNoFence __NF_(_interlockedbittestandreset)

#ifdef _WIN64
#define InterlockedBitTestAndSet64 _interlockedbittestandset64
#define InterlockedBitTestAndSet64Acquire __ACQ_(_interlockedbittestandset64)
#define InterlockedBitTestAndSet64Release __REL_(_interlockedbittestandset64)
#define InterlockedBitTestAndSet64NoFence __NF_(_interlockedbittestandset64)

#define InterlockedBitTestAndReset64 _interlockedbittestandreset64
#define InterlockedBitTestAndReset64Acquire __ACQ_(_interlockedbittestandreset64)
#define InterlockedBitTestAndReset64Release __REL_(_interlockedbittestandreset64)
#define InterlockedBitTestAndReset64NoFence __NF_(_interlockedbittestandreset64)
#endif /* _WIN64 */

#define InterlockedAdd _InterlockedAdd
#define InterlockedAddAcquire __ACQ_(_InterlockedAdd)
#define InterlockedAddRelease __REL_(_InterlockedAdd)
#define InterlockedAddNoFence __NF_(_InterlockedAdd)

#define InterlockedAdd64 _InterlockedAdd64
#define InterlockedAddAcquire64 __ACQ_(_InterlockedAdd64)
#define InterlockedAddRelease64 __REL_(_InterlockedAdd64)
#define InterlockedAddNoFence64 __NF_(_InterlockedAdd64)

#define InterlockedAnd _InterlockedAnd
#define InterlockedAndAcquire __ACQ_(_InterlockedAnd)
#define InterlockedAndRelease __REL_(_InterlockedAnd)
#define InterlockedAndNoFence __NF_(_InterlockedAnd)

#define InterlockedAnd8 _InterlockedAnd8
#ifdef _M_ARM
#define InterlockedAndAcquire8 _InterlockedAnd8_acq
#define InterlockedAndRelease8 _InterlockedAnd8_rel
#define InterlockedAndNoFence8 _InterlockedAnd8_nf
#elif defined(_M_IA64)
#define InterlockedAnd8Acquire  _InterlockedAnd8_acq
#define InterlockedAnd8Release  _InterlockedAnd8_rel
#endif // _M_ARM

#define InterlockedAnd16 _InterlockedAnd16
#ifdef _M_ARM
#define InterlockedAndAcquire16 _InterlockedAnd16_acq
#define InterlockedAndRelease16 _InterlockedAnd16_rel
#define InterlockedAndNoFence16 _InterlockedAnd16_nf
#elif defined(_M_IA64)
#define InterlockedAnd16Acquire _InterlockedAnd16_acq
#define InterlockedAnd16Release _InterlockedAnd16_rel
#endif // _M_ARM

#define InterlockedAnd64 _InterlockedAnd64
#ifdef _M_ARM
#define InterlockedAndAcquire64 __ACQ_(_InterlockedAnd64)
#define InterlockedAndRelease64 __REL_(_InterlockedAnd64)
#define InterlockedAndNoFence64 __NF_(_InterlockedAnd64)
#else // _M_ARM
#define InterlockedAnd64Acquire __ACQ_(_InterlockedAnd64)
#define InterlockedAnd64Release __REL_(_InterlockedAnd64)
#define InterlockedAnd64NoFence __NF_(_InterlockedAnd64)
#endif // _M_ARM

#ifdef _WIN64
#define InterlockedAndAffinity InterlockedAnd64
#else
#define InterlockedAndAffinity InterlockedAnd
#endif // _WIN64

#define InterlockedCompareExchange _InterlockedCompareExchange
#define InterlockedCompareExchangeAcquire __ACQ_(_InterlockedCompareExchange)
#define InterlockedCompareExchangeRelease __REL_(_InterlockedCompareExchange)
#define InterlockedCompareExchangeNoFence __NF_(_InterlockedCompareExchange)

#define InterlockedCompareExchange16 _InterlockedCompareExchange16
#define InterlockedCompareExchangeAcquire16 __ACQ_(_InterlockedCompareExchange16)
#define InterlockedCompareExchangeRelease16 __REL_(_InterlockedCompareExchange16)
#define InterlockedCompareExchangeNoFence16 __NF_(_InterlockedCompareExchange16)

#define InterlockedCompareExchange64 _InterlockedCompareExchange64
#define InterlockedCompareExchangeAcquire64 __ACQ_(_InterlockedCompareExchange64)
#define InterlockedCompareExchangeRelease64 __REL_(_InterlockedCompareExchange64)
#define InterlockedCompareExchangeNoFence64 __NF_(_InterlockedCompareExchange64)

#ifdef _WIN64
#define InterlockedCompareExchange128 _InterlockedCompareExchange128
#endif // _WIN64

#ifdef _M_IA64
#define InterlockedCompare64Exchange128         _InterlockedCompare64Exchange128
#define InterlockedCompare64ExchangeAcquire128  _InterlockedCompare64Exchange128_acq
#define InterlockedCompare64ExchangeRelease128  _InterlockedCompare64Exchange128_rel
#endif // _M_IA64

#define InterlockedCompareExchangePointer _InterlockedCompareExchangePointer
#define InterlockedCompareExchangePointerAcquire __ACQ_(_InterlockedCompareExchangePointer)
#define InterlockedCompareExchangePointerRelease __REL_(_InterlockedCompareExchangePointer)
#define InterlockedCompareExchangePointerNoFence __NF_(_InterlockedCompareExchangePointer)

#define InterlockedDecrement _InterlockedDecrement
#define InterlockedDecrementAcquire __ACQ_(_InterlockedDecrement)
#define InterlockedDecrementRelease __REL_(_InterlockedDecrement)
#define InterlockedDecrementNoFence __NF_(_InterlockedDecrement)

#define InterlockedDecrement16 _InterlockedDecrement16
#define InterlockedDecrementAcquire16 __ACQ_(_InterlockedDecrement16)
#define InterlockedDecrementRelease16 __REL_(_InterlockedDecrement16)
#define InterlockedDecrementNoFence16 __NF_(_InterlockedDecrement16)

#define InterlockedDecrement64 _InterlockedDecrement64
#define InterlockedDecrementAcquire64 __ACQ_(_InterlockedDecrement64)
#define InterlockedDecrementRelease64 __REL_(_InterlockedDecrement64)
#define InterlockedDecrementNoFence64 __NF_(_InterlockedDecrement64)

#ifdef _WIN64
#define InterlockedDecrementSizeT(a) InterlockedDecrement64((LONG64 *)a)
#define InterlockedDecrementSizeTNoFence(a) InterlockedDecrementNoFence64((LONG64 *)a)
#else
#define InterlockedDecrementSizeT(a) InterlockedDecrement((LONG *)a)
#define InterlockedDecrementSizeTNoFence(a) InterlockedDecrementNoFence((LONG *)a)
#endif // _WIN64

#define InterlockedExchange _InterlockedExchange
#define InterlockedExchangeAcquire __ACQ_(_InterlockedExchange)
/* No release here */
#define InterlockedExchangeNoFence __NF_(_InterlockedExchange)

#if (_MSC_VER >= 1600)
#define InterlockedExchange8 _InterlockedExchange8
#endif // (_MSC_VER >= 1600)

#define InterlockedExchange16 _InterlockedExchange16
/* No release here */
#define InterlockedExchangeAcquire16 __ACQ_(_InterlockedExchange16)
#define InterlockedExchangeNoFence16 __NF_(_InterlockedExchange16)

#define InterlockedExchange64 _InterlockedExchange64
#define InterlockedExchangeAcquire64 __ACQ_(_InterlockedExchange64)
/* No release here */
#define InterlockedExchangeNoFence64 __NF_(_InterlockedExchange64)

#define InterlockedExchangePointer _InterlockedExchangePointer
#define InterlockedExchangePointerAcquire __ACQ_(_InterlockedExchangePointer)
/* No release here */
#define InterlockedExchangePointerNoFence __NF_(_InterlockedExchangePointer)

#define InterlockedExchangeAdd _InterlockedExchangeAdd
#define InterlockedExchangeAddAcquire __ACQ_(_InterlockedExchangeAdd)
#define InterlockedExchangeAddRelease __REL_(_InterlockedExchangeAdd)
#define InterlockedExchangeAddNoFence __NF_(_InterlockedExchangeAdd)

#define InterlockedExchangeAdd64 _InterlockedExchangeAdd64
#define InterlockedExchangeAddAcquire64 __ACQ_(_InterlockedExchangeAdd64)
#define InterlockedExchangeAddRelease64 __REL_(_InterlockedExchangeAdd64)
#define InterlockedExchangeAddNoFence64 __NF_(_InterlockedExchangeAdd64)

#ifdef _WIN64
#define InterlockedExchangeAddSizeT(a, b) InterlockedExchangeAdd64((LONG64 *)a, b)
#define InterlockedExchangeAddSizeTAcquire(a, b) InterlockedExchangeAddAcquire64((LONG64 *)a, b)
#define InterlockedExchangeAddSizeTNoFence(a, b) InterlockedExchangeAddNoFence64((LONG64 *)a, b)
#else
#define InterlockedExchangeAddSizeT(a, b) InterlockedExchangeAdd((LONG *)a, b)
#define InterlockedExchangeAddSizeTAcquire(a, b) InterlockedExchangeAddAcquire((LONG *)a, b)
#define InterlockedExchangeAddSizeTNoFence(a, b) InterlockedExchangeAddNoFence((LONG *)a, b)
#endif // _WIN64

#define InterlockedIncrement _InterlockedIncrement
#define InterlockedIncrementAcquire __ACQ_(_InterlockedIncrement)
#define InterlockedIncrementRelease __REL_(_InterlockedIncrement)
#define InterlockedIncrementNoFence __NF_(_InterlockedIncrement)

#define InterlockedIncrement16 _InterlockedIncrement16
#define InterlockedIncrementAcquire16 __ACQ_(_InterlockedIncrement16)
#define InterlockedIncrementRelease16 __REL_(_InterlockedIncrement16)
#define InterlockedIncrementNoFence16 __NF_(_InterlockedIncrement16)

#define InterlockedIncrement64 _InterlockedIncrement64
#define InterlockedIncrementAcquire64 __ACQ_(_InterlockedIncrement64)
#define InterlockedIncrementRelease64 __REL_(_InterlockedIncrement64)
#define InterlockedIncrementNoFence64 __NF_(_InterlockedIncrement64)

#ifdef _WIN64
#define InterlockedIncrementSizeT(a) InterlockedIncrement64((LONG64 *)a)
#define InterlockedIncrementSizeTNoFence(a) InterlockedIncrementNoFence64((LONG64 *)a)
#else
#define InterlockedIncrementSizeT(a) InterlockedIncrement((LONG *)a)
#define InterlockedIncrementSizeTNoFence(a) InterlockedIncrementNoFence((LONG *)a)
#endif // _WIN64

#define InterlockedOr _InterlockedOr
#define InterlockedOrAcquire __ACQ_(_InterlockedOr)
#define InterlockedOrRelease __REL_(_InterlockedOr)
#define InterlockedOrNoFence __NF_(_InterlockedOr)

#define InterlockedOr8 _InterlockedOr8
#ifdef _M_ARM
#define InterlockedOrAcquire8 _InterlockedOr8_acq
#define InterlockedOrRelease8 _InterlockedOr8_rel
#define InterlockedOrNoFence8 _InterlockedOr8_nf
#elif defined(_M_IA64)
#define InterlockedOr8Acquire  _InterlockedOr8_acq
#define InterlockedOr8Release  _InterlockedOr8_rel
#endif // _M_ARM

#define InterlockedOr16 _InterlockedOr16
#ifdef _M_ARM
#define InterlockedOrAcquire16 _InterlockedOr16_acq
#define InterlockedOrRelease16 _InterlockedOr16_rel
#define InterlockedOrNoFence16 _InterlockedOr16_nf
#elif defined(_M_IA64)
#define InterlockedOr16Acquire _InterlockedOr16_acq
#define InterlockedOr16Release _InterlockedOr16_rel
#endif // _M_ARM

#define InterlockedOr64 _InterlockedOr64
#ifdef _M_ARM
#define InterlockedOrAcquire64 _InterlockedOr64_acq
#define InterlockedOrRelease64 _InterlockedOr64_rel
#define InterlockedOrNoFence64 _InterlockedOr64_nf
#elif defined(_M_IA64) || defined(_M_AMD64)
#define InterlockedOr64Acquire __ACQ_(_InterlockedOr64)
#define InterlockedOr64Release __REL_(_InterlockedOr64)
#define InterlockedOr64NoFence __NF_(_InterlockedOr64)
#endif // _M_ARM

#ifdef _WIN64
#define InterlockedOrAffinity InterlockedOr64
#else
#define InterlockedOrAffinity InterlockedOr
#endif // _WIN64

#define InterlockedXor _InterlockedXor
#define InterlockedXorAcquire __ACQ_(_InterlockedXor)
#define InterlockedXorRelease __REL_(_InterlockedXor)
#define InterlockedXorNoFence __NF_(_InterlockedXor)

#define InterlockedXor8 _InterlockedXor8
#ifdef _M_ARM
#define InterlockedXorAcquire8 _InterlockedXor8_acq
#define InterlockedXorRelease8 _InterlockedXor8_rel
#define InterlockedXorNoFence8 _InterlockedXor8_nf
#elif defined(_M_IA64)
#define InterlockedXor8Acquire _InterlockedXor8_acq
#define InterlockedXor8Release _InterlockedXor8_rel
#endif /* _M_ARM */

#define InterlockedXor16 _InterlockedXor16
#ifdef _M_ARM
#define InterlockedXorAcquire16 _InterlockedXor16_acq
#define InterlockedXorRelease16 _InterlockedXor16_rel
#define InterlockedXorNoFence16 _InterlockedXor16_nf
#elif defined(_M_IA64)
#define InterlockedXor16Acquire _InterlockedXor16_acq
#define InterlockedXor16Release _InterlockedXor16_rel
#endif /* _M_ARM */

#define InterlockedXor64 _InterlockedXor64
#ifdef _M_ARM
#define InterlockedXorAcquire64 _InterlockedXor64_acq
#define InterlockedXorRelease64 _InterlockedXor64_rel
#define InterlockedXorNoFence64 _InterlockedXor64_nf
#elif defined(_M_IA64) || defined(_M_AMD64)
#define InterlockedXor64Acquire __ACQ_(_InterlockedXor64)
#define InterlockedXor64Release __REL_(_InterlockedXor64)
#define InterlockedXor64NoFence __NF_(_InterlockedXor64)
#endif /* _M_ARM */

#ifdef _M_IX86

#undef _InterlockedExchange64
#define _InterlockedExchange64 _InlineInterlockedExchange64
FORCEINLINE
LONG64
_InlineInterlockedExchange64(
    _Inout_ _Interlocked_operand_ volatile LONG64 *Target,
    _In_ LONG64 Value)
{
    LONG64 Old, Prev;
    for (Old = *Target; ; Old = Prev)
    {
        Prev = _InterlockedCompareExchange64(Target, Value, Old);
        if (Prev == Old)
            return Prev;
    }
}

#undef _InterlockedAdd64
#define _InterlockedAdd64 _InlineInterlockedAdd64
FORCEINLINE
LONG64
_InlineInterlockedAdd64(
    _Inout_ _Interlocked_operand_ volatile LONG64 *Target,
    _In_ LONG64 Value)
{
    LONG64 Old, Prev, New;
    for (Old = *Target; ; Old = Prev)
    {
        New = Old + Value;
        Prev = _InterlockedCompareExchange64(Target, New, Old);
        if (Prev == Old)
            return New;
    }
}

#undef _InterlockedExchangeAdd64
#define _InterlockedExchangeAdd64 _InlineInterlockedExchangeAdd64
FORCEINLINE
LONG64
_InlineInterlockedExchangeAdd64(
    _Inout_ _Interlocked_operand_ volatile LONG64 *Target,
    _In_ LONG64 Value
    )
{
    LONG64 Old, Prev, New;
    for (Old = *Target; ; Old = Prev)
    {
        New = Old + Value;
        Prev = _InterlockedCompareExchange64(Target, New, Old);
        if (Prev == Old)
            return Prev;
    }
}

#undef _InterlockedAnd64
#define _InterlockedAnd64 _InlineInterlockedAnd64
FORCEINLINE
LONG64
_InlineInterlockedAnd64(
    _Inout_ _Interlocked_operand_ volatile LONG64 *Target,
    _In_ LONG64 Value)
{
    LONG64 Old, Prev, New;
    for (Old = *Target; ; Old = Prev)
    {
        New = Old & Value;
        Prev = _InterlockedCompareExchange64(Target, New, Old);
        if (Prev == Old)
            return New;
    }
}

#undef _InterlockedOr64
#define _InterlockedOr64 _InlineInterlockedOr64
FORCEINLINE
LONG64
_InlineInterlockedOr64(
    _Inout_ _Interlocked_operand_ volatile LONG64 *Target,
    _In_ LONG64 Value)
{
    LONG64 Old, Prev, New;
    for (Old = *Target; ; Old = Prev)
    {
        New = Old | Value;
        Prev = _InterlockedCompareExchange64(Target, New, Old);
        if (Prev == Old)
            return New;
    }
}

#undef _InterlockedXor64
#define _InterlockedXor64 _InlineInterlockedXor64
FORCEINLINE
LONG64
_InlineInterlockedXor64(
    _Inout_ _Interlocked_operand_ volatile LONG64 *Target,
    _In_ LONG64 Value)
{
    LONG64 Old, Prev, New;
    for (Old = *Target; ; Old = Prev)
    {
        New = Old ^ Value;
        Prev = _InterlockedCompareExchange64(Target, New, Old);
        if (Prev == Old)
            return New;
    }
}

#undef _InterlockedIncrement64
#define _InterlockedIncrement64 _InlineInterlockedIncrement64
FORCEINLINE
LONG64
_InlineInterlockedIncrement64(
    _Inout_ _Interlocked_operand_ volatile LONG64 *Target)
{
    return _InterlockedAdd64(Target, 1);
}

#undef _InterlockedDecrement64
#define _InterlockedDecrement64 _InlineInterlockedDecrement64
FORCEINLINE
LONG64
_InlineInterlockedDecrement64(
    _Inout_ _Interlocked_operand_ volatile LONG64 *Target)
{
    return _InterlockedAdd64(Target, -1);
}

#undef _InterlockedExchangePointer
#define _InterlockedExchangePointer _InlineInterlockedExchangePointer
FORCEINLINE
_Ret_writes_(_Inexpressible_(Unknown))
PVOID
_InterlockedExchangePointer(
    _Inout_ _At_(*Destination, _Pre_writable_byte_size_(_Inexpressible_(Unknown))
        _Post_writable_byte_size_(_Inexpressible_(Unknown)))
        _Interlocked_operand_ volatile PVOID *Destination,
    _In_opt_ PVOID Value)
{
    return (PVOID)InterlockedExchange((volatile long *)Destination, (long)Value);
}

#undef _InterlockedCompareExchangePointer
#define _InterlockedCompareExchangePointer _InlineInterlockedCompareExchangePointer
FORCEINLINE
_Ret_writes_(_Inexpressible_(Unknown))
PVOID
_InterlockedCompareExchangePointer(
    _Inout_ _At_(*Destination, _Pre_writable_byte_size_(_Inexpressible_(Unknown))
        _Post_writable_byte_size_(_Inexpressible_(Unknown)))
        _Interlocked_operand_ volatile PVOID *Destination,
    _In_opt_ PVOID ExChange,
    _In_opt_ PVOID Comperand)
{
    return (PVOID)InterlockedCompareExchange((volatile long *)Destination,
                                             (long)ExChange,
                                             (long)Comperand);
}

#endif /* _M_IX86 */

#ifdef _M_AMD64

FORCEINLINE
LONG64
_InterlockedAdd64(
    _Inout_ _Interlocked_operand_ volatile LONG64 *Target,
    _In_ LONG64 Value)

{
    return _InterlockedExchangeAdd64(Target, Value) + Value;
}

#endif /* _M_AMD64 */

#ifdef _M_IA64

#undef _InterlockedBitTestAndSet
#define _InterlockedBitTestAndSet InterlockedBitTestAndSet_Inline
FORCEINLINE
BOOLEAN
_InterlockedBitTestAndSet(
    _Inout_ _Interlocked_operand_ volatile LONG *Target,
    _In_ LONG Bit)
{
    ULONG Mask = 1 << (Bit & 31);
    return (BOOLEAN)((InterlockedOr(&Target[Bit / 32], Mask) & Mask) != 0);
}

#undef _InterlockedBitTestAndReset
#define _InterlockedBitTestAndReset InterlockedBitTestAndReset_Inline
FORCEINLINE
BOOLEAN
_InterlockedBitTestAndReset(
    _Inout_ _Interlocked_operand_ volatile LONG *Target,
    _In_ LONG Bit)
{
    ULONG Mask = 1 << (Bit & 31);
    return (BOOLEAN)((InterlockedAnd(&Target[Bit / 32], ~Mask) & Mask) != 0);
}

#undef _InterlockedBitTestAndSet64
#define _InterlockedBitTestAndSet64 InterlockedBitTestAndSet64_Inline
FORCEINLINE
BOOLEAN
_InterlockedBitTestAndSet64(
    _Inout_ _Interlocked_operand_ volatile LONG64 *Target,
    _In_ LONG64 Bit)
{
    ULONG64 Mask = 1LL << (Bit & 63);
    return (BOOLEAN)((InterlockedOr64(&Target[Bit / 64], Mask) & Mask) != 0);
}

#undef _InterlockedBitTestAndReset64
#define _InterlockedBitTestAndReset64 InterlockedBitTestAndReset64_Inline
FORCEINLINE
BOOLEAN
_InterlockedBitTestAndReset64(
    _Inout_ _Interlocked_operand_ volatile LONG64 *Target,
    _In_ LONG64 Bit)
{
    ULONG64 Mask = 1LL << (Bit & 63);
    return (BOOLEAN)((InterlockedAnd64(&Target[Bit / 64], ~Mask) & Mask) != 0);
}

#undef _InterlockedBitTestAndComplement
#define _InterlockedBitTestAndComplement InterlockedBitTestAndComplement_Inline
FORCEINLINE
BOOLEAN
_InterlockedBitTestAndComplement(
    _Inout_ _Interlocked_operand_ volatile LONG *Target,
    _In_ LONG Bit)
{
    ULONG Mask = 1 << (Bit & 31);
    return (BOOLEAN)((InterlockedXor(&Target[Bit / 32], Mask) & Mask) != 0);
}

#undef _InterlockedBitTestAndComplement64
#define _InterlockedBitTestAndComplement64 InterlockedBitTestAndComplement64_Inline
FORCEINLINE
BOOLEAN
_InterlockedBitTestAndComplement64(
    _Inout_ _Interlocked_operand_ volatile LONG64 *Target,
    _In_ LONG64 Bit)
{
    ULONG64 Mask = 1LL << (Bit & 63);
    return (BOOLEAN)((InterlockedXor64(&Target[Bit / 64], Mask) & Mask) != 0);
}

#endif /* M_IA64 */

/******************************************************************************
 *                              Kernel Types                                  *
 ******************************************************************************/

typedef struct _PROCESSOR_GROUP_INFO {
  UCHAR MaximumProcessorCount;
  UCHAR ActiveProcessorCount;
  UCHAR Reserved[38];
  KAFFINITY ActiveProcessorMask;
} PROCESSOR_GROUP_INFO, *PPROCESSOR_GROUP_INFO;

typedef enum _PROCESSOR_CACHE_TYPE {
  CacheUnified,
  CacheInstruction,
  CacheData,
  CacheTrace
} PROCESSOR_CACHE_TYPE;

typedef struct _CACHE_DESCRIPTOR {
  UCHAR Level;
  UCHAR Associativity;
  USHORT LineSize;
  ULONG Size;
  PROCESSOR_CACHE_TYPE Type;
} CACHE_DESCRIPTOR, *PCACHE_DESCRIPTOR;

typedef struct _NUMA_NODE_RELATIONSHIP {
  ULONG NodeNumber;
  UCHAR Reserved[20];
  GROUP_AFFINITY GroupMask;
} NUMA_NODE_RELATIONSHIP, *PNUMA_NODE_RELATIONSHIP;

typedef struct _CACHE_RELATIONSHIP {
  UCHAR Level;
  UCHAR Associativity;
  USHORT LineSize;
  ULONG CacheSize;
  PROCESSOR_CACHE_TYPE Type;
  UCHAR Reserved[20];
  GROUP_AFFINITY GroupMask;
} CACHE_RELATIONSHIP, *PCACHE_RELATIONSHIP;

typedef struct _GROUP_RELATIONSHIP {
  USHORT MaximumGroupCount;
  USHORT ActiveGroupCount;
  UCHAR Reserved[20];
  PROCESSOR_GROUP_INFO GroupInfo[ANYSIZE_ARRAY];
} GROUP_RELATIONSHIP, *PGROUP_RELATIONSHIP;

typedef enum _LOGICAL_PROCESSOR_RELATIONSHIP {
  RelationProcessorCore,
  RelationNumaNode,
  RelationCache,
  RelationProcessorPackage,
  RelationGroup,
  RelationAll = 0xffff
} LOGICAL_PROCESSOR_RELATIONSHIP;

typedef struct _PROCESSOR_RELATIONSHIP {
  UCHAR Flags;
  UCHAR Reserved[21];
  USHORT GroupCount;
  _Field_size_(GroupCount) GROUP_AFFINITY GroupMask[ANYSIZE_ARRAY];
} PROCESSOR_RELATIONSHIP, *PPROCESSOR_RELATIONSHIP;

typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION {
  ULONG_PTR ProcessorMask;
  LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
  _ANONYMOUS_UNION union {
    struct {
      UCHAR Flags;
    } ProcessorCore;
    struct {
      ULONG NodeNumber;
    } NumaNode;
    CACHE_DESCRIPTOR Cache;
    ULONGLONG Reserved[2];
  } DUMMYUNIONNAME;
} SYSTEM_LOGICAL_PROCESSOR_INFORMATION, *PSYSTEM_LOGICAL_PROCESSOR_INFORMATION;

typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX {
  LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
  ULONG Size;
  _ANONYMOUS_UNION union {
    PROCESSOR_RELATIONSHIP Processor;
    NUMA_NODE_RELATIONSHIP NumaNode;
    CACHE_RELATIONSHIP Cache;
    GROUP_RELATIONSHIP Group;
  } DUMMYUNIONNAME;
} SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, *PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX;



#if defined(__ROS_LONG64__)
#undef InterlockedExchange
#define InterlockedExchange(a,b) _InterlockedExchange((long*)a,b)
#undef InterlockedExchangeAdd
#define InterlockedExchangeAdd(a,b) _InterlockedExchangeAdd((long*)a,b)
#undef InterlockedCompareExchange
#define InterlockedCompareExchange(a,b,c) _InterlockedCompareExchange((long*)a,b,c)
#undef InterlockedIncrement
#define InterlockedIncrement(a) _InterlockedIncrement((long*)a)
#undef InterlockedDecrement
#define InterlockedDecrement(a) _InterlockedDecrement((long*)a)
#endif

#undef __C89_NAMELESS
#undef __C89_NAMELESSSTRUCTNAME
#undef __C89_NAMELESSSTRUCTNAME1
#undef __C89_NAMELESSSTRUCTNAME2
#undef __C89_NAMELESSSTRUCTNAME3
#undef __C89_NAMELESSSTRUCTNAME4
#undef __C89_NAMELESSSTRUCTNAME5
#undef __C89_NAMELESSUNIONNAME
#undef __C89_NAMELESSUNIONNAME1
#undef __C89_NAMELESSUNIONNAME2
#undef __C89_NAMELESSUNIONNAME3
#undef __C89_NAMELESSUNIONNAME4
#undef __C89_NAMELESSUNIONNAME5
#undef __C89_NAMELESSUNIONNAME6
#undef __C89_NAMELESSUNIONNAME7
#undef __C89_NAMELESSUNIONNAME8

#if !defined(__WINESRC__) && !defined(WINE_NO_NAMELESS_EXTENSION)
# ifdef __GNUC__
   /* Anonymous structs support starts with gcc 2.96/g++ 2.95 */
#  if (__GNUC__ > 2) || ((__GNUC__ == 2) && ((__GNUC_MINOR__ > 95) || ((__GNUC_MINOR__ == 95) && defined(__cplusplus))))
#   define __C89_NAMELESS __extension__
#  endif
# elif defined(_MSC_VER)
#  define __C89_NAMELESS
# endif
#endif

#ifdef __C89_NAMELESS
# define __C89_NAMELESSSTRUCTNAME
# define __C89_NAMELESSSTRUCTNAME1
# define __C89_NAMELESSSTRUCTNAME2
# define __C89_NAMELESSSTRUCTNAME3
# define __C89_NAMELESSSTRUCTNAME4
# define __C89_NAMELESSSTRUCTNAME5
# define __C89_NAMELESSUNIONNAME
# define __C89_NAMELESSUNIONNAME1
# define __C89_NAMELESSUNIONNAME2
# define __C89_NAMELESSUNIONNAME3
# define __C89_NAMELESSUNIONNAME4
# define __C89_NAMELESSUNIONNAME5
# define __C89_NAMELESSUNIONNAME6
# define __C89_NAMELESSUNIONNAME7
# define __C89_NAMELESSUNIONNAME8
#else
# define __C89_NAMELESS
# define __C89_NAMELESSSTRUCTNAME DUMMYSTRUCTNAME
# define __C89_NAMELESSSTRUCTNAME1 DUMMYSTRUCTNAME1
# define __C89_NAMELESSSTRUCTNAME2 DUMMYSTRUCTNAME2
# define __C89_NAMELESSSTRUCTNAME3 DUMMYSTRUCTNAME3
# define __C89_NAMELESSSTRUCTNAME4 DUMMYSTRUCTNAME4
# define __C89_NAMELESSSTRUCTNAME5 DUMMYSTRUCTNAME5
# define __C89_NAMELESSUNIONNAME DUMMYUNIONNAME
# define __C89_NAMELESSUNIONNAME1 DUMMYUNIONNAME1
# define __C89_NAMELESSUNIONNAME2 DUMMYUNIONNAME2
# define __C89_NAMELESSUNIONNAME3 DUMMYUNIONNAME3
# define __C89_NAMELESSUNIONNAME4 DUMMYUNIONNAME4
# define __C89_NAMELESSUNIONNAME5 DUMMYUNIONNAME5
# define __C89_NAMELESSUNIONNAME6 DUMMYUNIONNAME6
# define __C89_NAMELESSUNIONNAME7 DUMMYUNIONNAME7
# define __C89_NAMELESSUNIONNAME8 DUMMYUNIONNAME8
#endif

#define DECLSPEC_HIDDEN

/*#ifdef _WINE*/
#if defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 3)))
# define __WINE_ALLOC_SIZE(x) __attribute__((__alloc_size__(x)))
#else
# define __WINE_ALLOC_SIZE(x)
#endif
/*#endif*/

#ifdef __GNUC__
# define _HAVE_INT64
# ifndef _INTEGRAL_MAX_BITS
#  define _INTEGRAL_MAX_BITS 64
# endif
# undef __int64
# define __int64 long long
#elif (defined(__WATCOMC__) || defined(_MSC_VER)) && (defined(_INTEGRAL_MAX_BITS) && _INTEGRAL_MAX_BITS >= 64 )
# define _HAVE_INT64
#endif /* __GNUC__/__WATCOMC */

#ifdef _MSC_VER
# pragma warning(push)
# pragma warning(disable:4201)
# pragma warning(disable:4214)
# pragma warning(disable:4820)
#endif

#define ACE_OBJECT_TYPE_PRESENT           0x00000001
#define ACE_INHERITED_OBJECT_TYPE_PRESENT 0x00000002

/* also in ddk/ntifs.h */
#define COMPRESSION_FORMAT_NONE         (0x0000)
#define COMPRESSION_FORMAT_DEFAULT      (0x0001)
#define COMPRESSION_FORMAT_LZNT1        (0x0002)
#define COMPRESSION_ENGINE_STANDARD     (0x0000)
#define COMPRESSION_ENGINE_MAXIMUM      (0x0100)
#define COMPRESSION_ENGINE_HIBER        (0x0200)
#define ACCESS_ALLOWED_ACE_TYPE         (0x0)
#define ACCESS_DENIED_ACE_TYPE          (0x1)
#define SYSTEM_AUDIT_ACE_TYPE           (0x2)
#define SYSTEM_ALARM_ACE_TYPE           (0x3)
/*end ntifs.h */

#define REG_STANDARD_FORMAT 1
#define REG_LATEST_FORMAT   2
#define REG_NO_COMPRESSION  4

#ifndef WIN32_NO_STATUS

#define STATUS_WAIT_0                    ((DWORD)0x00000000)
#define STATUS_ABANDONED_WAIT_0          ((DWORD)0x00000080)
#define STATUS_USER_APC                  ((DWORD)0x000000C0)
#define STATUS_TIMEOUT                   ((DWORD)0x00000102)
#define STATUS_PENDING                   ((DWORD)0x00000103)
#define STATUS_SEGMENT_NOTIFICATION      ((DWORD)0x40000005)
#define STATUS_GUARD_PAGE_VIOLATION      ((DWORD)0x80000001)
#define STATUS_DATATYPE_MISALIGNMENT     ((DWORD)0x80000002)
#define STATUS_BREAKPOINT                ((DWORD)0x80000003)
#define STATUS_SINGLE_STEP               ((DWORD)0x80000004)
#define STATUS_ACCESS_VIOLATION          ((DWORD)0xC0000005)
#define STATUS_IN_PAGE_ERROR             ((DWORD)0xC0000006)
#define STATUS_INVALID_HANDLE            ((DWORD)0xC0000008)
#define STATUS_NO_MEMORY                 ((DWORD)0xC0000017)
#define STATUS_ILLEGAL_INSTRUCTION       ((DWORD)0xC000001D)
#define STATUS_NONCONTINUABLE_EXCEPTION  ((DWORD)0xC0000025)
#define STATUS_INVALID_DISPOSITION       ((DWORD)0xC0000026)
#define STATUS_ARRAY_BOUNDS_EXCEEDED     ((DWORD)0xC000008C)
#define STATUS_FLOAT_DENORMAL_OPERAND    ((DWORD)0xC000008D)
#define STATUS_FLOAT_DIVIDE_BY_ZERO      ((DWORD)0xC000008E)
#define STATUS_FLOAT_INEXACT_RESULT      ((DWORD)0xC000008F)
#define STATUS_FLOAT_INVALID_OPERATION   ((DWORD)0xC0000090)
#define STATUS_FLOAT_OVERFLOW            ((DWORD)0xC0000091)
#define STATUS_FLOAT_STACK_CHECK         ((DWORD)0xC0000092)
#define STATUS_FLOAT_UNDERFLOW           ((DWORD)0xC0000093)
#define STATUS_INTEGER_DIVIDE_BY_ZERO    ((DWORD)0xC0000094)
#define STATUS_INTEGER_OVERFLOW          ((DWORD)0xC0000095)
#define STATUS_PRIVILEGED_INSTRUCTION    ((DWORD)0xC0000096)
#define STATUS_STACK_OVERFLOW            ((DWORD)0xC00000FD)
#define STATUS_CONTROL_C_EXIT            ((DWORD)0xC000013A)
#define STATUS_FLOAT_MULTIPLE_FAULTS     ((DWORD)0xC00002B4)
#define STATUS_FLOAT_MULTIPLE_TRAPS      ((DWORD)0xC00002B5)
#define STATUS_REG_NAT_CONSUMPTION       ((DWORD)0xC00002C9)
#define STATUS_SXS_EARLY_DEACTIVATION    ((DWORD)0xC015000F)
#define STATUS_SXS_INVALID_DEACTIVATION  ((DWORD)0xC0150010)

#define DBG_EXCEPTION_HANDLED       ((DWORD)0x00010001)
#define DBG_CONTINUE                ((DWORD)0x00010002)
#define DBG_TERMINATE_THREAD        ((DWORD)0x40010003)
#define DBG_TERMINATE_PROCESS       ((DWORD)0x40010004)
#define DBG_CONTROL_C               ((DWORD)0x40010005)
#define DBG_CONTROL_BREAK           ((DWORD)0x40010008)
#define DBG_COMMAND_EXCEPTION       ((DWORD)0x40010009)
#define DBG_EXCEPTION_NOT_HANDLED   ((DWORD)0x80010001)

#endif /* WIN32_NO_STATUS */

#define INVALID_FILE_ATTRIBUTES    ((DWORD)-1)

/* Also in ddk/winddk.h */
#define FILE_LIST_DIRECTORY        0x00000001
#define FILE_READ_DATA            0x00000001
#define FILE_ADD_FILE            0x00000002
#define FILE_WRITE_DATA            0x00000002
#define FILE_ADD_SUBDIRECTORY        0x00000004
#define FILE_APPEND_DATA        0x00000004
#define FILE_CREATE_PIPE_INSTANCE    0x00000004
#define FILE_READ_EA            0x00000008
#define FILE_READ_PROPERTIES        0x00000008
#define FILE_WRITE_EA            0x00000010
#define FILE_WRITE_PROPERTIES        0x00000010
#define FILE_EXECUTE            0x00000020
#define FILE_TRAVERSE            0x00000020
#define FILE_DELETE_CHILD        0x00000040
#define FILE_READ_ATTRIBUTES        0x00000080
#define FILE_WRITE_ATTRIBUTES        0x00000100

#define FILE_SHARE_READ            0x00000001
#define FILE_SHARE_WRITE        0x00000002
#define FILE_SHARE_DELETE        0x00000004
#define FILE_SHARE_VALID_FLAGS        0x00000007

#define FILE_ATTRIBUTE_READONLY            0x00000001
#define FILE_ATTRIBUTE_HIDDEN            0x00000002
#define FILE_ATTRIBUTE_SYSTEM            0x00000004
#define FILE_ATTRIBUTE_DIRECTORY        0x00000010
#define FILE_ATTRIBUTE_ARCHIVE            0x00000020
#define FILE_ATTRIBUTE_DEVICE            0x00000040
#define FILE_ATTRIBUTE_NORMAL            0x00000080
#define FILE_ATTRIBUTE_TEMPORARY        0x00000100
#define FILE_ATTRIBUTE_SPARSE_FILE        0x00000200
#define FILE_ATTRIBUTE_REPARSE_POINT        0x00000400
#define FILE_ATTRIBUTE_COMPRESSED        0x00000800
#define FILE_ATTRIBUTE_OFFLINE            0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED    0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED        0x00004000
#define FILE_ATTRIBUTE_INTEGRITY_STREAM   0x00008000
#define FILE_ATTRIBUTE_VIRTUAL 0x00010000
#define FILE_ATTRIBUTE_VALID_FLAGS        0x00007fb7
#define FILE_ATTRIBUTE_VALID_SET_FLAGS        0x000031a7

#define FILE_COPY_STRUCTURED_STORAGE        0x00000041
#define FILE_STRUCTURED_STORAGE            0x00000441

#define FILE_VALID_OPTION_FLAGS            0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS        0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS    0x00000032
#define FILE_VALID_SET_FLAGS            0x00000036

#define FILE_DIRECTORY_FILE        0x00000001
#define FILE_WRITE_THROUGH        0x00000002
#define FILE_SEQUENTIAL_ONLY        0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING    0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT    0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020
#define FILE_NON_DIRECTORY_FILE        0x00000040
#define FILE_CREATE_TREE_CONNECTION    0x00000080
#define FILE_COMPLETE_IF_OPLOCKED    0x00000100
#define FILE_NO_EA_KNOWLEDGE        0x00000200
#define FILE_OPEN_REMOTE_INSTANCE    0x00000400
#define FILE_RANDOM_ACCESS        0x00000800
#define FILE_DELETE_ON_CLOSE        0x00001000
#define FILE_OPEN_BY_FILE_ID        0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT    0x00004000
#define FILE_NO_COMPRESSION        0x00008000
#define FILE_RESERVE_OPFILTER        0x00100000
#define FILE_OPEN_REPARSE_POINT        0x00200000
#define FILE_OPEN_NO_RECALL        0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY    0x00800000

#define FILE_ALL_ACCESS \
  (STANDARD_RIGHTS_REQUIRED | \
   SYNCHRONIZE | \
   0x1FF)

#define FILE_GENERIC_EXECUTE \
  (STANDARD_RIGHTS_EXECUTE | \
   FILE_READ_ATTRIBUTES | \
   FILE_EXECUTE | \
   SYNCHRONIZE)

#define FILE_GENERIC_READ \
  (STANDARD_RIGHTS_READ | \
   FILE_READ_DATA | \
   FILE_READ_ATTRIBUTES | \
   FILE_READ_EA | \
   SYNCHRONIZE)

#define FILE_GENERIC_WRITE \
  (STANDARD_RIGHTS_WRITE | \
   FILE_WRITE_DATA | \
   FILE_WRITE_ATTRIBUTES | \
   FILE_WRITE_EA | \
   FILE_APPEND_DATA | \
   SYNCHRONIZE)
/* end winddk.h */
/* also in ddk/ntifs.h */
#define FILE_NOTIFY_CHANGE_FILE_NAME    0x00000001
#define FILE_NOTIFY_CHANGE_DIR_NAME    0x00000002
#define FILE_NOTIFY_CHANGE_NAME        0x00000003
#define FILE_NOTIFY_CHANGE_ATTRIBUTES    0x00000004
#define FILE_NOTIFY_CHANGE_SIZE        0x00000008
#define FILE_NOTIFY_CHANGE_LAST_WRITE    0x00000010
#define FILE_NOTIFY_CHANGE_LAST_ACCESS    0x00000020
#define FILE_NOTIFY_CHANGE_CREATION    0x00000040
#define FILE_NOTIFY_CHANGE_EA        0x00000080
#define FILE_NOTIFY_CHANGE_SECURITY    0x00000100
#define FILE_NOTIFY_CHANGE_STREAM_NAME    0x00000200
#define FILE_NOTIFY_CHANGE_STREAM_SIZE    0x00000400
#define FILE_NOTIFY_CHANGE_STREAM_WRITE    0x00000800
#define FILE_NOTIFY_VALID_MASK        0x00000fff

#define FILE_CASE_SENSITIVE_SEARCH        0x00000001
#define FILE_CASE_PRESERVED_NAMES         0x00000002
#define FILE_UNICODE_ON_DISK              0x00000004
#define FILE_PERSISTENT_ACLS              0x00000008
#define FILE_FILE_COMPRESSION             0x00000010
#define FILE_VOLUME_QUOTAS                0x00000020
#define FILE_SUPPORTS_SPARSE_FILES        0x00000040
#define FILE_SUPPORTS_REPARSE_POINTS      0x00000080
#define FILE_SUPPORTS_REMOTE_STORAGE      0x00000100
#define FS_LFN_APIS                       0x00004000
#define FILE_VOLUME_IS_COMPRESSED         0x00008000
#define FILE_SUPPORTS_OBJECT_IDS          0x00010000
#define FILE_SUPPORTS_ENCRYPTION          0x00020000
#define FILE_NAMED_STREAMS                0x00040000
#define FILE_READ_ONLY_VOLUME             0x00080000
#define FILE_SEQUENTIAL_WRITE_ONCE        0x00100000
#define FILE_SUPPORTS_TRANSACTIONS        0x00200000
#define FILE_SUPPORTS_HARD_LINKS          0x00400000
#define FILE_SUPPORTS_EXTENDED_ATTRIBUTES 0x00800000
#define FILE_SUPPORTS_OPEN_BY_FILE_ID     0x01000000
#define FILE_SUPPORTS_USN_JOURNAL         0x02000000
#define FILE_SUPPORTS_INTEGRITY_STREAMS   0x04000000
#define FILE_SUPPORTS_BLOCK_REFCOUNTING   0x08000000
#define FILE_SUPPORTS_SPARSE_VDL          0x10000000
#define FILE_DAX_VOLUME                   0x20000000

#define IO_COMPLETION_QUERY_STATE       0x0001
#define IO_COMPLETION_MODIFY_STATE      0x0002
#define IO_COMPLETION_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3)
/* end ntifs.h */

/* also in ddk/winddk.h */
#define DUPLICATE_CLOSE_SOURCE        0x00000001
#define DUPLICATE_SAME_ACCESS        0x00000002
/* end winddk.k */

#define MAILSLOT_NO_MESSAGE    ((DWORD)-1)
#define MAILSLOT_WAIT_FOREVER    ((DWORD)-1)
#define PROCESS_TERMINATE    1
#define PROCESS_CREATE_THREAD    2
#define PROCESS_SET_SESSIONID    4
#define PROCESS_VM_OPERATION    8
#define PROCESS_VM_READ    16
#define PROCESS_VM_WRITE    32
#define PROCESS_CREATE_PROCESS    128
#define PROCESS_SET_QUOTA    256
#define PROCESS_SET_INFORMATION    512
#define PROCESS_QUERY_INFORMATION    1024
#define PROCESS_SUSPEND_RESUME    2048
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#define PROCESS_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0xFFF)
#define PROCESS_DUP_HANDLE    64
#define THREAD_TERMINATE    1
#define THREAD_SUSPEND_RESUME    2
#define THREAD_GET_CONTEXT    8
#define THREAD_SET_CONTEXT    16
#define THREAD_SET_INFORMATION    32
#define THREAD_QUERY_INFORMATION    64
#define THREAD_SET_THREAD_TOKEN    128
#define THREAD_IMPERSONATE    256
#define THREAD_DIRECT_IMPERSONATION    0x200
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#define THREAD_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3FF)
#define MUTANT_QUERY_STATE    0x0001
#define MUTANT_ALL_ACCESS    (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|MUTANT_QUERY_STATE)
#define TIMER_QUERY_STATE    0x0001
#define TIMER_MODIFY_STATE    0x0002
#define TIMER_ALL_ACCESS    (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|TIMER_QUERY_STATE|TIMER_MODIFY_STATE)
#define THREAD_BASE_PRIORITY_LOWRT    15
#define THREAD_BASE_PRIORITY_MAX    2
#define THREAD_BASE_PRIORITY_MIN    (-2)
#define THREAD_BASE_PRIORITY_IDLE    (-15)

#define PROCESS_SET_LIMITED_INFORMATION 0x2000
#define THREAD_RESUME 0x1000

#define SE_CREATE_TOKEN_NAME    TEXT("SeCreateTokenPrivilege")
#define SE_ASSIGNPRIMARYTOKEN_NAME    TEXT("SeAssignPrimaryTokenPrivilege")
#define SE_LOCK_MEMORY_NAME    TEXT("SeLockMemoryPrivilege")
#define SE_INCREASE_QUOTA_NAME    TEXT("SeIncreaseQuotaPrivilege")
#define SE_UNSOLICITED_INPUT_NAME    TEXT("SeUnsolicitedInputPrivilege")
#define SE_MACHINE_ACCOUNT_NAME TEXT("SeMachineAccountPrivilege")
#define SE_TCB_NAME    TEXT("SeTcbPrivilege")
#define SE_SECURITY_NAME    TEXT("SeSecurityPrivilege")
#define SE_TAKE_OWNERSHIP_NAME    TEXT("SeTakeOwnershipPrivilege")
#define SE_LOAD_DRIVER_NAME    TEXT("SeLoadDriverPrivilege")
#define SE_SYSTEM_PROFILE_NAME    TEXT("SeSystemProfilePrivilege")
#define SE_SYSTEMTIME_NAME    TEXT("SeSystemtimePrivilege")
#define SE_PROF_SINGLE_PROCESS_NAME    TEXT("SeProfileSingleProcessPrivilege")
#define SE_INC_BASE_PRIORITY_NAME    TEXT("SeIncreaseBasePriorityPrivilege")
#define SE_CREATE_PAGEFILE_NAME TEXT("SeCreatePagefilePrivilege")
#define SE_CREATE_PERMANENT_NAME    TEXT("SeCreatePermanentPrivilege")
#define SE_BACKUP_NAME TEXT("SeBackupPrivilege")
#define SE_RESTORE_NAME    TEXT("SeRestorePrivilege")
#define SE_SHUTDOWN_NAME    TEXT("SeShutdownPrivilege")
#define SE_DEBUG_NAME    TEXT("SeDebugPrivilege")
#define SE_AUDIT_NAME    TEXT("SeAuditPrivilege")
#define SE_SYSTEM_ENVIRONMENT_NAME    TEXT("SeSystemEnvironmentPrivilege")
#define SE_CHANGE_NOTIFY_NAME    TEXT("SeChangeNotifyPrivilege")
#define SE_REMOTE_SHUTDOWN_NAME    TEXT("SeRemoteShutdownPrivilege")
#define SE_UNDOCK_NAME    TEXT("SeUndockPrivilege")
#define SE_SYNC_AGENT_NAME    TEXT("SeSyncAgentPrivilege")
#define SE_ENABLE_DELEGATION_NAME    TEXT("SeEnableDelegationPrivilege")
#define SE_MANAGE_VOLUME_NAME    TEXT("SeManageVolumePrivilege")
#define SE_IMPERSONATE_NAME    TEXT("SeImpersonatePrivilege")
#define SE_CREATE_GLOBAL_NAME    TEXT("SeCreateGlobalPrivilege")

#define SE_GROUP_MANDATORY          0x00000001
#define SE_GROUP_ENABLED_BY_DEFAULT 0x00000002
#define SE_GROUP_ENABLED            0x00000004
#define SE_GROUP_OWNER              0x00000008
#define SE_GROUP_USE_FOR_DENY_ONLY  0x00000010
#define SE_GROUP_INTEGRITY          0x00000020
#define SE_GROUP_INTEGRITY_ENABLED  0x00000040
#define SE_GROUP_LOGON_ID           0xC0000000
#define SE_GROUP_RESOURCE           0x20000000
#define SE_GROUP_VALID_ATTRIBUTES   0xE000007F

/* FIXME: non-standard */
#define LANG_ESPERANTO      0x8f
#define LANG_WALON          0x90
#define LANG_CORNISH        0x92

/* FIXME: not present in the official headers */
#define LANG_MALAGASY       0x8d
#define LANG_GAELIC         0x94
#define LANG_SAAMI          0x3b
#define LANG_SUTU           0x30
#define LANG_TSONGA         0x31
#define LANG_VENDA          0x33
#define LANG_MANX_GAELIC    0x94
#define SUBLANG_PORTUGUESE_PORTUGAL   0x02

#define PROCESSOR_INTEL_386 386
#define PROCESSOR_INTEL_486 486
#define PROCESSOR_INTEL_PENTIUM 586
#define PROCESSOR_MIPS_R4000 4000
#define PROCESSOR_ALPHA_21064 21064
#define PROCESSOR_INTEL_IA64 2200
#define PROCESSOR_PPC_601 601
#define PROCESSOR_PPC_603 603
#define PROCESSOR_PPC_604 604
#define PROCESSOR_PPC_620 620
#define PROCESSOR_INTEL_860 860
#define PROCESSOR_AMD_X8664 8664
#define PROCESSOR_MIPS_R2000 2000
#define PROCESSOR_MIPS_R3000 3000
#define PROCESSOR_HITACHI_SH3 10003
#define PROCESSOR_HITACHI_SH3E 10004
#define PROCESSOR_HITACHI_SH4 10005
#define PROCESSOR_MOTOROLA_821 821
#define PROCESSOR_SHx_SH3 103
#define PROCESSOR_SHx_SH4 104
#define PROCESSOR_STRONGARM 2577
#define PROCESSOR_ARM720 1824
#define PROCESSOR_ARM820 2080
#define PROCESSOR_ARM920 2336
#define PROCESSOR_ARM_7TDMI 70001
#define PROCESSOR_ARCHITECTURE_INTEL 0
#define PROCESSOR_ARCHITECTURE_MIPS 1
#define PROCESSOR_ARCHITECTURE_ALPHA 2
#define PROCESSOR_ARCHITECTURE_PPC 3
#define PROCESSOR_ARCHITECTURE_SHX 4
#define PROCESSOR_ARCHITECTURE_ARM 5
#define PROCESSOR_ARCHITECTURE_IA64 6
#define PROCESSOR_ARCHITECTURE_ALPHA64 7
#define PROCESSOR_ARCHITECTURE_MSIL 8
#define PROCESSOR_ARCHITECTURE_AMD64 9
#define PROCESSOR_ARCHITECTURE_UNKNOWN 0xFFFF

/* Processor features */
#define PF_FLOATING_POINT_PRECISION_ERRATA       0
#define PF_FLOATING_POINT_EMULATED               1
#define PF_COMPARE_EXCHANGE_DOUBLE               2
#define PF_MMX_INSTRUCTIONS_AVAILABLE            3
#define PF_PPC_MOVEMEM_64BIT_OK                  4
#define PF_ALPHA_BYTE_INSTRUCTIONS               5
#define PF_XMMI_INSTRUCTIONS_AVAILABLE           6
#define PF_3DNOW_INSTRUCTIONS_AVAILABLE          7
#define PF_RDTSC_INSTRUCTION_AVAILABLE           8
#define PF_PAE_ENABLED                           9
#define PF_XMMI64_INSTRUCTIONS_AVAILABLE        10
#define PF_SSE_DAZ_MODE_AVAILABLE               11
#define PF_NX_ENABLED                           12
#define PF_SSE3_INSTRUCTIONS_AVAILABLE          13
#define PF_COMPARE_EXCHANGE128                  14
#define PF_COMPARE64_EXCHANGE128                15
#define PF_CHANNELS_ENABLED                     16
#define PF_XSAVE_ENABLED                        17
#define PF_ARM_VFP_32_REGISTERS_AVAILABLE       18
#define PF_ARM_NEON_INSTRUCTIONS_AVAILABLE      19
#define PF_SECOND_LEVEL_ADDRESS_TRANSLATION     20
#define PF_VIRT_FIRMWARE_ENABLED                21
#define PF_RDWRFSGSBASE_AVAILABLE               22
#define PF_FASTFAIL_AVAILABLE                   23
#define PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE     24
#define PF_ARM_64BIT_LOADSTORE_ATOMIC           25
#define PF_ARM_EXTERNAL_CACHE_AVAILABLE         26
#define PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE      27
#define PF_RDRAND_INSTRUCTION_AVAILABLE         28
#define PF_ARM_V8_INSTRUCTIONS_AVAILABLE        29
#define PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE 30
#define PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE  31

/* also in ddk/ntifs.h */
#define FILE_ACTION_ADDED                   0x00000001
#define FILE_ACTION_REMOVED                 0x00000002
#define FILE_ACTION_MODIFIED                0x00000003
#define FILE_ACTION_RENAMED_OLD_NAME        0x00000004
#define FILE_ACTION_RENAMED_NEW_NAME        0x00000005
#define FILE_ACTION_ADDED_STREAM            0x00000006
#define FILE_ACTION_REMOVED_STREAM          0x00000007
#define FILE_ACTION_MODIFIED_STREAM         0x00000008
#define FILE_ACTION_REMOVED_BY_DELETE       0x00000009
#define FILE_ACTION_ID_NOT_TUNNELLED        0x0000000A
#define FILE_ACTION_TUNNELLED_ID_COLLISION  0x0000000B
/* end ntifs.h */
#define HEAP_NO_SERIALIZE 1
#define HEAP_GROWABLE 2
#define HEAP_GENERATE_EXCEPTIONS 4
#define HEAP_ZERO_MEMORY 8
#define HEAP_REALLOC_IN_PLACE_ONLY 16
#define HEAP_TAIL_CHECKING_ENABLED 32
#define HEAP_FREE_CHECKING_ENABLED 64
#define HEAP_DISABLE_COALESCE_ON_FREE 128
#define HEAP_CREATE_ALIGN_16 0x10000
#define HEAP_CREATE_ENABLE_TRACING 0x20000
#define HEAP_CREATE_ENABLE_EXECUTE 0x00040000
#define HEAP_MAXIMUM_TAG 0xFFF
#define HEAP_PSEUDO_TAG_FLAG 0x8000
#define HEAP_TAG_SHIFT 16
#define HEAP_MAKE_TAG_FLAGS(b,o) ((DWORD)((b)+(o)<<16)))

#define KEY_QUERY_VALUE 1
#define KEY_SET_VALUE 2
#define KEY_CREATE_SUB_KEY 4
#define KEY_ENUMERATE_SUB_KEYS 8
#define KEY_NOTIFY 16
#define KEY_CREATE_LINK 32
#define KEY_WOW64_64KEY         0x00000100
#define KEY_WOW64_32KEY         0x00000200
#define KEY_WOW64_RES           0x00000300

#define KEY_WRITE 0x20006
#define KEY_EXECUTE 0x20019
#define KEY_READ 0x20019
#define KEY_ALL_ACCESS 0xf003f
#define REG_WHOLE_HIVE_VOLATILE    1
#define REG_REFRESH_HIVE    2
#define REG_NO_LAZY_FLUSH    4
#define REG_FORCE_RESTORE    8
#define REG_OPTION_RESERVED    0
#define REG_OPTION_NON_VOLATILE    0
#define REG_OPTION_VOLATILE    1
#define REG_OPTION_CREATE_LINK    2
#define REG_OPTION_BACKUP_RESTORE    4
#define REG_OPTION_OPEN_LINK    8
#define REG_LEGAL_OPTION    15
#define MAXIMUM_PROCESSORS 32
#define PAGE_NOACCESS    0x0001
#define PAGE_READONLY    0x0002
#define PAGE_READWRITE    0x0004
#define PAGE_WRITECOPY    0x0008
#define PAGE_EXECUTE    0x0010
#define PAGE_EXECUTE_READ    0x0020
#define PAGE_EXECUTE_READWRITE    0x0040
#define PAGE_EXECUTE_WRITECOPY    0x0080
#define PAGE_GUARD        0x0100
#define PAGE_NOCACHE        0x0200
#define PAGE_WRITECOMBINE    0x0400
#define MEM_COMMIT           0x1000
#define MEM_RESERVE          0x2000
#define MEM_DECOMMIT         0x4000
#define MEM_RELEASE          0x8000
#define MEM_FREE            0x10000
#define MEM_PRIVATE         0x20000
#define MEM_MAPPED          0x40000
#define MEM_RESET           0x80000
#define MEM_TOP_DOWN       0x100000
#define MEM_WRITE_WATCH       0x200000 /* 98/Me */
#define MEM_PHYSICAL       0x400000
#define MEM_4MB_PAGES    0x80000000
#define MEM_IMAGE        SEC_IMAGE
#define SEC_NO_CHANGE    0x00400000
#define SEC_FILE    0x00800000
#define SEC_IMAGE    0x01000000
#define SEC_VLM        0x02000000
#define SEC_RESERVE    0x04000000
#define SEC_COMMIT    0x08000000
#define SEC_NOCACHE    0x10000000
#define SEC_WRITECOMBINE 0x40000000
#define SEC_LARGE_PAGES  0x80000000
#define SEC_IMAGE_NO_EXECUTE (SEC_IMAGE | SEC_NOCACHE)
#define SECTION_MAP_EXECUTE_EXPLICIT 0x0020
#define SECTION_EXTEND_SIZE 16
#define SECTION_MAP_READ 4
#define SECTION_MAP_WRITE 2
#define SECTION_QUERY 1
#define SECTION_MAP_EXECUTE 8
#define SECTION_ALL_ACCESS 0xf001f
#define WRITE_WATCH_FLAG_RESET 0x01
#define MESSAGE_RESOURCE_UNICODE 1
#define RTL_CRITSECT_TYPE 0
#define RTL_RESOURCE_TYPE 1

#define AT_ROUND_TO_PAGE 0x40000000

#define IMAGE_SIZEOF_FILE_HEADER    20
#define IMAGE_FILE_RELOCS_STRIPPED    1
#define IMAGE_FILE_EXECUTABLE_IMAGE    2
#define IMAGE_FILE_LINE_NUMS_STRIPPED    4
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED    8
#define IMAGE_FILE_AGGRESIVE_WS_TRIM     16
#define IMAGE_FILE_LARGE_ADDRESS_AWARE    32
#define IMAGE_FILE_BYTES_REVERSED_LO    128
#define IMAGE_FILE_32BIT_MACHINE    256
#define IMAGE_FILE_DEBUG_STRIPPED    512
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP    1024
#define IMAGE_FILE_NET_RUN_FROM_SWAP    2048
#define IMAGE_FILE_SYSTEM    4096
#define IMAGE_FILE_DLL    8192
#define IMAGE_FILE_UP_SYSTEM_ONLY    16384
#define IMAGE_FILE_BYTES_REVERSED_HI    32768
#define IMAGE_FILE_MACHINE_UNKNOWN    0

#define IMAGE_FILE_MACHINE_AM33       0x1d3
#define IMAGE_FILE_MACHINE_AMD64      0x8664
#define IMAGE_FILE_MACHINE_ARM        0x1c0
#define IMAGE_FILE_MACHINE_ARMNT      0x1c4
#define IMAGE_FILE_MACHINE_EBC        0xebc
#define IMAGE_FILE_MACHINE_I386       0x14c
#define IMAGE_FILE_MACHINE_IA64       0x200
#define IMAGE_FILE_MACHINE_M32R       0x9041
#define IMAGE_FILE_MACHINE_MIPS16     0x266
#define IMAGE_FILE_MACHINE_MIPSFPU    0x366
#define IMAGE_FILE_MACHINE_MIPSFPU16  0x466
#define IMAGE_FILE_MACHINE_POWERPC    0x1f0
#define IMAGE_FILE_MACHINE_POWERPCFP  0x1f1
#define IMAGE_FILE_MACHINE_R4000      0x166
#define IMAGE_FILE_MACHINE_SH3        0x1a2
#define IMAGE_FILE_MACHINE_SH3E       0x01a4
#define IMAGE_FILE_MACHINE_SH3DSP     0x1a3
#define IMAGE_FILE_MACHINE_SH4        0x1a6
#define IMAGE_FILE_MACHINE_SH5        0x1a8
#define IMAGE_FILE_MACHINE_THUMB      0x1c2
#define IMAGE_FILE_MACHINE_WCEMIPSV2  0x169
#define IMAGE_FILE_MACHINE_R3000      0x162
#define IMAGE_FILE_MACHINE_R10000     0x168
#define IMAGE_FILE_MACHINE_ALPHA      0x184
#define IMAGE_FILE_MACHINE_ALPHA64    0x0284
#define IMAGE_FILE_MACHINE_AXP64      IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_CEE        0xC0EE
#define IMAGE_FILE_MACHINE_TRICORE    0x0520
#define IMAGE_FILE_MACHINE_CEF        0x0CEF
#define IMAGE_FILE_MACHINE_ARM64      0xAA64

#define IMAGE_FILE_EXPORT_DIRECTORY        0
#define IMAGE_FILE_IMPORT_DIRECTORY        1
#define IMAGE_FILE_RESOURCE_DIRECTORY        2
#define IMAGE_FILE_EXCEPTION_DIRECTORY        3
#define IMAGE_FILE_SECURITY_DIRECTORY        4
#define IMAGE_FILE_BASE_RELOCATION_TABLE    5
#define IMAGE_FILE_DEBUG_DIRECTORY        6
#define IMAGE_FILE_DESCRIPTION_STRING        7
#define IMAGE_FILE_MACHINE_VALUE        8  /* Mips */
#define IMAGE_FILE_THREAD_LOCAL_STORAGE        9
#define IMAGE_FILE_CALLBACK_DIRECTORY        10

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_OS2_SIGNATURE 0x454E
#define IMAGE_OS2_SIGNATURE_LE 0x454C
#define IMAGE_VXD_SIGNATURE 0x454C
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#ifdef _WIN64
#define IMAGE_NT_OPTIONAL_HDR_MAGIC IMAGE_NT_OPTIONAL_HDR64_MAGIC
#else
#define IMAGE_NT_OPTIONAL_HDR_MAGIC IMAGE_NT_OPTIONAL_HDR32_MAGIC
#endif
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC 0x107
#define IMAGE_SEPARATE_DEBUG_SIGNATURE 0x4944
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_ROM_OPTIONAL_HEADER 56
#define IMAGE_SIZEOF_STD_OPTIONAL_HEADER 28
#define IMAGE_SIZEOF_NT_OPTIONAL_HEADER 224
#define IMAGE_SIZEOF_SHORT_NAME 8
#define IMAGE_SIZEOF_SECTION_HEADER 40
#define IMAGE_SIZEOF_SYMBOL 18
#define IMAGE_SIZEOF_AUX_SYMBOL 18
#define IMAGE_SIZEOF_RELOCATION 10
#define IMAGE_SIZEOF_BASE_RELOCATION 8
#define IMAGE_SIZEOF_LINENUMBER 6
#define IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR 60
#define SIZEOF_RFPO_DATA 16

#define IMAGE_SUBSYSTEM_UNKNOWN                      0
#define IMAGE_SUBSYSTEM_NATIVE                       1
#define IMAGE_SUBSYSTEM_WINDOWS_GUI                  2
#define IMAGE_SUBSYSTEM_WINDOWS_CUI                  3
#define IMAGE_SUBSYSTEM_OS2_CUI                      5
#define IMAGE_SUBSYSTEM_POSIX_CUI                    7
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS               8
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI               9
#define IMAGE_SUBSYSTEM_EFI_APPLICATION             10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER     11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER          12
#define IMAGE_SUBSYSTEM_EFI_ROM                     13
#define IMAGE_SUBSYSTEM_XBOX                        14

#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY 0x0080
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT 0x0100
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200
#define IMAGE_DLLCHARACTERISTICS_NO_SEH 0x0400
#define IMAGE_DLLCHARACTERISTICS_NO_BIND 0x0800
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER 0x2000
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000
#define IMAGE_FIRST_SECTION(h) ((PIMAGE_SECTION_HEADER) ((ULONG_PTR)h+FIELD_OFFSET(IMAGE_NT_HEADERS,OptionalHeader)+((PIMAGE_NT_HEADERS)(h))->FileHeader.SizeOfOptionalHeader))
#define IMAGE_DIRECTORY_ENTRY_EXPORT    0
#define IMAGE_DIRECTORY_ENTRY_IMPORT    1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE    2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION    3
#define IMAGE_DIRECTORY_ENTRY_SECURITY    4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC    5
#define IMAGE_DIRECTORY_ENTRY_DEBUG    6
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT    7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR    8
#define IMAGE_DIRECTORY_ENTRY_TLS    9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT    11
#define IMAGE_DIRECTORY_ENTRY_IAT    12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT    13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    14
#define IMAGE_SCN_TYPE_REG 0
#define IMAGE_SCN_TYPE_DSECT 1
//#define IMAGE_SCN_TYPE_NOLOAD 2
#define IMAGE_SCN_TYPE_GROUP 4
#define IMAGE_SCN_TYPE_NO_PAD 8
#define IMAGE_SCN_CNT_CODE 32
#define IMAGE_SCN_CNT_INITIALIZED_DATA 64
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 128
#define IMAGE_SCN_LNK_OTHER 256
#define IMAGE_SCN_LNK_INFO 512
#define IMAGE_SCN_LNK_REMOVE 2048
#define IMAGE_SCN_LNK_COMDAT 4096
#define IMAGE_SCN_MEM_FARDATA 0x8000
#define IMAGE_SCN_MEM_PURGEABLE 0x20000
#define IMAGE_SCN_MEM_16BIT 0x20000
#define IMAGE_SCN_MEM_LOCKED  0x40000
#define IMAGE_SCN_MEM_PRELOAD 0x80000
#define IMAGE_SCN_ALIGN_1BYTES 0x100000
#define IMAGE_SCN_ALIGN_2BYTES 0x200000
#define IMAGE_SCN_ALIGN_4BYTES 0x300000
#define IMAGE_SCN_ALIGN_8BYTES 0x400000
#define IMAGE_SCN_ALIGN_16BYTES 0x500000
#define IMAGE_SCN_ALIGN_32BYTES 0x600000
#define IMAGE_SCN_ALIGN_64BYTES 0x700000
#define IMAGE_SCN_LNK_NRELOC_OVFL 0x1000000
#define IMAGE_SCN_MEM_DISCARDABLE 0x2000000
#define IMAGE_SCN_MEM_NOT_CACHED 0x4000000
#define IMAGE_SCN_MEM_NOT_PAGED 0x8000000
#define IMAGE_SCN_MEM_SHARED 0x10000000
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000
#define IMAGE_SYM_UNDEFINED    0
#define IMAGE_SYM_ABSOLUTE (-1)
#define IMAGE_SYM_DEBUG    (-2)
#define IMAGE_SYM_TYPE_NULL 0
#define IMAGE_SYM_TYPE_VOID 1
#define IMAGE_SYM_TYPE_CHAR 2
#define IMAGE_SYM_TYPE_SHORT 3
#define IMAGE_SYM_TYPE_INT 4
#define IMAGE_SYM_TYPE_LONG 5
#define IMAGE_SYM_TYPE_FLOAT 6
#define IMAGE_SYM_TYPE_DOUBLE 7
#define IMAGE_SYM_TYPE_STRUCT 8
#define IMAGE_SYM_TYPE_UNION 9
#define IMAGE_SYM_TYPE_ENUM 10
#define IMAGE_SYM_TYPE_MOE 11
#define IMAGE_SYM_TYPE_BYTE 12
#define IMAGE_SYM_TYPE_WORD 13
#define IMAGE_SYM_TYPE_UINT 14
#define IMAGE_SYM_TYPE_DWORD 15
#define IMAGE_SYM_TYPE_PCODE 32768
#define IMAGE_SYM_DTYPE_NULL 0
#define IMAGE_SYM_DTYPE_POINTER 1
#define IMAGE_SYM_DTYPE_FUNCTION 2
#define IMAGE_SYM_DTYPE_ARRAY 3
#define IMAGE_SYM_CLASS_END_OF_FUNCTION    (-1)
#define IMAGE_SYM_CLASS_NULL 0
#define IMAGE_SYM_CLASS_AUTOMATIC 1
#define IMAGE_SYM_CLASS_EXTERNAL 2
#define IMAGE_SYM_CLASS_STATIC 3
#define IMAGE_SYM_CLASS_REGISTER 4
#define IMAGE_SYM_CLASS_EXTERNAL_DEF 5
#define IMAGE_SYM_CLASS_LABEL 6
#define IMAGE_SYM_CLASS_UNDEFINED_LABEL 7
#define IMAGE_SYM_CLASS_MEMBER_OF_STRUCT 8
#define IMAGE_SYM_CLASS_ARGUMENT 9
#define IMAGE_SYM_CLASS_STRUCT_TAG 10
#define IMAGE_SYM_CLASS_MEMBER_OF_UNION 11
#define IMAGE_SYM_CLASS_UNION_TAG 12
#define IMAGE_SYM_CLASS_TYPE_DEFINITION 13
#define IMAGE_SYM_CLASS_UNDEFINED_STATIC 14
#define IMAGE_SYM_CLASS_ENUM_TAG 15
#define IMAGE_SYM_CLASS_MEMBER_OF_ENUM 16
#define IMAGE_SYM_CLASS_REGISTER_PARAM 17
#define IMAGE_SYM_CLASS_BIT_FIELD 18
#define IMAGE_SYM_CLASS_FAR_EXTERNAL 68
#define IMAGE_SYM_CLASS_BLOCK 100
#define IMAGE_SYM_CLASS_FUNCTION 101
#define IMAGE_SYM_CLASS_END_OF_STRUCT 102
#define IMAGE_SYM_CLASS_FILE 103
#define IMAGE_SYM_CLASS_SECTION 104
#define IMAGE_SYM_CLASS_WEAK_EXTERNAL 105
#define IMAGE_COMDAT_SELECT_NODUPLICATES 1
#define IMAGE_COMDAT_SELECT_ANY 2
#define IMAGE_COMDAT_SELECT_SAME_SIZE 3
#define IMAGE_COMDAT_SELECT_EXACT_MATCH 4
#define IMAGE_COMDAT_SELECT_ASSOCIATIVE 5
#define IMAGE_COMDAT_SELECT_LARGEST 6
#define IMAGE_COMDAT_SELECT_NEWEST 7
#define IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY 1
#define IMAGE_WEAK_EXTERN_SEARCH_LIBRARY 2
#define IMAGE_WEAK_EXTERN_SEARCH_ALIAS 3
#define IMAGE_REL_I386_ABSOLUTE 0
#define IMAGE_REL_I386_DIR16 1
#define IMAGE_REL_I386_REL16 2
#define IMAGE_REL_I386_DIR32 6
#define IMAGE_REL_I386_DIR32NB 7
#define IMAGE_REL_I386_SEG12 9
#define IMAGE_REL_I386_SECTION 10
#define IMAGE_REL_I386_SECREL 11
#define IMAGE_REL_I386_REL32 20
#define IMAGE_REL_MIPS_ABSOLUTE 0
#define IMAGE_REL_MIPS_REFHALF 1
#define IMAGE_REL_MIPS_REFWORD 2
#define IMAGE_REL_MIPS_JMPADDR 3
#define IMAGE_REL_MIPS_REFHI 4
#define IMAGE_REL_MIPS_REFLO 5
#define IMAGE_REL_MIPS_GPREL 6
#define IMAGE_REL_MIPS_LITERAL 7
#define IMAGE_REL_MIPS_SECTION 10
#define IMAGE_REL_MIPS_SECREL 11
#define IMAGE_REL_MIPS_SECRELLO 12
#define IMAGE_REL_MIPS_SECRELHI 13
#define IMAGE_REL_MIPS_REFWORDNB 34
#define IMAGE_REL_MIPS_PAIR 35
#define IMAGE_REL_ALPHA_ABSOLUTE 0
#define IMAGE_REL_ALPHA_REFLONG 1
#define IMAGE_REL_ALPHA_REFQUAD 2
#define IMAGE_REL_ALPHA_GPREL32 3
#define IMAGE_REL_ALPHA_LITERAL 4
#define IMAGE_REL_ALPHA_LITUSE 5
#define IMAGE_REL_ALPHA_GPDISP 6
#define IMAGE_REL_ALPHA_BRADDR 7
#define IMAGE_REL_ALPHA_HINT 8
#define IMAGE_REL_ALPHA_INLINE_REFLONG 9
#define IMAGE_REL_ALPHA_REFHI 10
#define IMAGE_REL_ALPHA_REFLO 11
#define IMAGE_REL_ALPHA_PAIR 12
#define IMAGE_REL_ALPHA_MATCH 13
#define IMAGE_REL_ALPHA_SECTION 14
#define IMAGE_REL_ALPHA_SECREL 15
#define IMAGE_REL_ALPHA_REFLONGNB 16
#define IMAGE_REL_ALPHA_SECRELLO 17
#define IMAGE_REL_ALPHA_SECRELHI 18
#define IMAGE_REL_PPC_ABSOLUTE 0
#define IMAGE_REL_PPC_ADDR64 1
#define IMAGE_REL_PPC_ADDR32 2
#define IMAGE_REL_PPC_ADDR24 3
#define IMAGE_REL_PPC_ADDR16 4
#define IMAGE_REL_PPC_ADDR14 5
#define IMAGE_REL_PPC_REL24 6
#define IMAGE_REL_PPC_REL14 7
#define IMAGE_REL_PPC_TOCREL16 8
#define IMAGE_REL_PPC_TOCREL14 9
#define IMAGE_REL_PPC_ADDR32NB 10
#define IMAGE_REL_PPC_SECREL 11
#define IMAGE_REL_PPC_SECTION 12
#define IMAGE_REL_PPC_IFGLUE 13
#define IMAGE_REL_PPC_IMGLUE 14
#define IMAGE_REL_PPC_SECREL16 15
#define IMAGE_REL_PPC_REFHI 16
#define IMAGE_REL_PPC_REFLO 17
#define IMAGE_REL_PPC_PAIR 18
#define IMAGE_REL_PPC_TYPEMASK 255
#define IMAGE_REL_PPC_NEG 256
#define IMAGE_REL_PPC_BRTAKEN 512
#define IMAGE_REL_PPC_BRNTAKEN 1024
#define IMAGE_REL_PPC_TOCDEFN 2048
#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGH 1
#define IMAGE_REL_BASED_LOW 2
#define IMAGE_REL_BASED_HIGHLOW 3
#define IMAGE_REL_BASED_HIGHADJ 4
#define IMAGE_REL_BASED_MIPS_JMPADDR 5
#define IMAGE_REL_BASED_MIPS_JMPADDR16 9
#define IMAGE_REL_BASED_IA64_IMM64 9
#define IMAGE_REL_BASED_DIR64 10
#define IMAGE_ARCHIVE_START_SIZE 8
#define IMAGE_ARCHIVE_START "!<arch>\n"
#define IMAGE_ARCHIVE_END "`\n"
#define IMAGE_ARCHIVE_PAD "\n"
#define IMAGE_ARCHIVE_LINKER_MEMBER "/               "
#define IMAGE_ARCHIVE_LONGNAMES_MEMBER "//              "
#define IMAGE_RESOURCE_NAME_IS_STRING 0x80000000
#define IMAGE_RESOURCE_DATA_IS_DIRECTORY 0x80000000
#define IMAGE_DEBUG_TYPE_UNKNOWN 0
#define IMAGE_DEBUG_TYPE_COFF 1
#define IMAGE_DEBUG_TYPE_CODEVIEW 2
#define IMAGE_DEBUG_TYPE_FPO 3
#define IMAGE_DEBUG_TYPE_MISC 4
#define IMAGE_DEBUG_TYPE_EXCEPTION 5
#define IMAGE_DEBUG_TYPE_FIXUP 6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC 7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC 8
#define FRAME_FPO 0
#define FRAME_TRAP 1
#define FRAME_TSS 2
#define FRAME_NONFPO 3
#define IMAGE_DEBUG_MISC_EXENAME 1
#define N_BTMASK 0x000F
#define N_TMASK 0x0030
#define N_TMASK1 0x00C0
#define N_TMASK2 0x00F0
#define N_BTSHFT 4
#define N_TSHIFT 2
#define IS_TEXT_UNICODE_ASCII16 1
#define IS_TEXT_UNICODE_REVERSE_ASCII16 16
#define IS_TEXT_UNICODE_STATISTICS 2
#define IS_TEXT_UNICODE_REVERSE_STATISTICS 32
#define IS_TEXT_UNICODE_CONTROLS 4
#define IS_TEXT_UNICODE_REVERSE_CONTROLS 64
#define IS_TEXT_UNICODE_SIGNATURE 8
#define IS_TEXT_UNICODE_REVERSE_SIGNATURE 128
#define IS_TEXT_UNICODE_ILLEGAL_CHARS 256
#define IS_TEXT_UNICODE_ODD_LENGTH 512
#define IS_TEXT_UNICODE_DBCS_LEADBYTE 1024
#define IS_TEXT_UNICODE_NULL_BYTES 4096
#define IS_TEXT_UNICODE_UNICODE_MASK 15
#define IS_TEXT_UNICODE_REVERSE_MASK 240
#define IS_TEXT_UNICODE_NOT_UNICODE_MASK 3840
#define IS_TEXT_UNICODE_NOT_ASCII_MASK 61440
#define SERVICE_KERNEL_DRIVER 1
#define SERVICE_FILE_SYSTEM_DRIVER 2
#define SERVICE_ADAPTER 4
#define SERVICE_RECOGNIZER_DRIVER 8
#define SERVICE_DRIVER (SERVICE_KERNEL_DRIVER|SERVICE_FILE_SYSTEM_DRIVER|SERVICE_RECOGNIZER_DRIVER)
#define SERVICE_WIN32_OWN_PROCESS 16
#define SERVICE_WIN32_SHARE_PROCESS 32
#define SERVICE_WIN32 (SERVICE_WIN32_OWN_PROCESS|SERVICE_WIN32_SHARE_PROCESS)
#define SERVICE_INTERACTIVE_PROCESS 256
#define SERVICE_TYPE_ALL (SERVICE_WIN32|SERVICE_ADAPTER|SERVICE_DRIVER|SERVICE_INTERACTIVE_PROCESS)
#define SERVICE_BOOT_START 0
#define SERVICE_SYSTEM_START 1
#define SERVICE_AUTO_START 2
#define SERVICE_DEMAND_START 3
#define SERVICE_DISABLED 4
#define SERVICE_ERROR_IGNORE 0
#define SERVICE_ERROR_NORMAL 1
#define SERVICE_ERROR_SEVERE 2
#define SERVICE_ERROR_CRITICAL 3

#define DLL_PROCESS_DETACH    0
#define DLL_PROCESS_ATTACH    1
#define DLL_THREAD_ATTACH    2
#define DLL_THREAD_DETACH    3
#ifdef __WINESRC__
#define DLL_WINE_PREATTACH    8 /* Never called, but defined for compatibility with Wine source */
#endif
#define TAPE_ABSOLUTE_POSITION 0
#define TAPE_LOGICAL_POSITION 1
#define TAPE_PSEUDO_LOGICAL_POSITION 2
#define TAPE_REWIND 0
#define TAPE_ABSOLUTE_BLOCK 1
#define TAPE_LOGICAL_BLOCK 2
#define TAPE_PSEUDO_LOGICAL_BLOCK 3
#define TAPE_SPACE_END_OF_DATA 4
#define TAPE_SPACE_RELATIVE_BLOCKS 5
#define TAPE_SPACE_FILEMARKS 6
#define TAPE_SPACE_SEQUENTIAL_FMKS 7
#define TAPE_SPACE_SETMARKS 8
#define TAPE_SPACE_SEQUENTIAL_SMKS 9
#define TAPE_DRIVE_FIXED 1
#define TAPE_DRIVE_SELECT 2
#define TAPE_DRIVE_INITIATOR 4
#define TAPE_DRIVE_ERASE_SHORT 16
#define TAPE_DRIVE_ERASE_LONG 32
#define TAPE_DRIVE_ERASE_BOP_ONLY 64
#define TAPE_DRIVE_ERASE_IMMEDIATE 128
#define TAPE_DRIVE_TAPE_CAPACITY 256
#define TAPE_DRIVE_TAPE_REMAINING 512
#define TAPE_DRIVE_FIXED_BLOCK 1024
#define TAPE_DRIVE_VARIABLE_BLOCK 2048
#define TAPE_DRIVE_WRITE_PROTECT 4096
#define TAPE_DRIVE_EOT_WZ_SIZE 8192
#define TAPE_DRIVE_ECC 0x10000
#define TAPE_DRIVE_COMPRESSION 0x20000
#define TAPE_DRIVE_PADDING 0x40000
#define TAPE_DRIVE_REPORT_SMKS 0x80000
#define TAPE_DRIVE_GET_ABSOLUTE_BLK 0x100000
#define TAPE_DRIVE_GET_LOGICAL_BLK 0x200000
#define TAPE_DRIVE_SET_EOT_WZ_SIZE 0x400000
#define TAPE_DRIVE_EJECT_MEDIA 0x1000000
#define TAPE_DRIVE_CLEAN_REQUESTS 0x2000000
#define TAPE_DRIVE_SET_CMP_BOP_ONLY 0x4000000
#define TAPE_DRIVE_RESERVED_BIT 0x80000000
#define TAPE_DRIVE_LOAD_UNLOAD 0x80000001
#define TAPE_DRIVE_TENSION 0x80000002
#define TAPE_DRIVE_LOCK_UNLOCK 0x80000004
#define TAPE_DRIVE_REWIND_IMMEDIATE 0x80000008
#define TAPE_DRIVE_SET_BLOCK_SIZE 0x80000010
#define TAPE_DRIVE_LOAD_UNLD_IMMED 0x80000020
#define TAPE_DRIVE_TENSION_IMMED 0x80000040
#define TAPE_DRIVE_LOCK_UNLK_IMMED 0x80000080
#define TAPE_DRIVE_SET_ECC 0x80000100
#define TAPE_DRIVE_SET_COMPRESSION 0x80000200
#define TAPE_DRIVE_SET_PADDING 0x80000400
#define TAPE_DRIVE_SET_REPORT_SMKS 0x80000800
#define TAPE_DRIVE_ABSOLUTE_BLK 0x80001000
#define TAPE_DRIVE_ABS_BLK_IMMED 0x80002000
#define TAPE_DRIVE_LOGICAL_BLK 0x80004000
#define TAPE_DRIVE_LOG_BLK_IMMED 0x80008000
#define TAPE_DRIVE_END_OF_DATA 0x80010000
#define TAPE_DRIVE_RELATIVE_BLKS 0x80020000
#define TAPE_DRIVE_FILEMARKS 0x80040000
#define TAPE_DRIVE_SEQUENTIAL_FMKS 0x80080000
#define TAPE_DRIVE_SETMARKS 0x80100000
#define TAPE_DRIVE_SEQUENTIAL_SMKS 0x80200000
#define TAPE_DRIVE_REVERSE_POSITION 0x80400000
#define TAPE_DRIVE_SPACE_IMMEDIATE 0x80800000
#define TAPE_DRIVE_WRITE_SETMARKS 0x81000000
#define TAPE_DRIVE_WRITE_FILEMARKS 0x82000000
#define TAPE_DRIVE_WRITE_SHORT_FMKS 0x84000000
#define TAPE_DRIVE_WRITE_LONG_FMKS 0x88000000
#define TAPE_DRIVE_WRITE_MARK_IMMED 0x90000000
#define TAPE_DRIVE_FORMAT 0xA0000000
#define TAPE_DRIVE_FORMAT_IMMEDIATE 0xC0000000
#define TAPE_DRIVE_HIGH_FEATURES 0x80000000
#define TAPE_FIXED_PARTITIONS    0
#define TAPE_INITIATOR_PARTITIONS    2
#define TAPE_SELECT_PARTITIONS    1
#define TAPE_FILEMARKS    1
#define TAPE_LONG_FILEMARKS    3
#define TAPE_SETMARKS    0
#define TAPE_SHORT_FILEMARKS    2
#define TAPE_ERASE_LONG 1
#define TAPE_ERASE_SHORT 0
#define TAPE_LOAD 0
#define TAPE_UNLOAD 1
#define TAPE_TENSION 2
#define TAPE_LOCK 3
#define TAPE_UNLOCK 4
#define TAPE_FORMAT 5
#if (_WIN32_WINNT >= 0x0500)
#define VER_MINORVERSION 0x0000001
#define VER_MAJORVERSION 0x0000002
#define VER_BUILDNUMBER 0x0000004
#define VER_PLATFORMID 0x0000008
#define VER_SERVICEPACKMINOR 0x0000010
#define VER_SERVICEPACKMAJOR 0x0000020
#define VER_SUITENAME 0x0000040
#define VER_PRODUCT_TYPE 0x0000080
#define VER_EQUAL 1
#define VER_GREATER 2
#define VER_GREATER_EQUAL 3
#define VER_LESS 4
#define VER_LESS_EQUAL 5
#define VER_AND 6
#define VER_OR 7
#endif

#define VER_PLATFORM_WIN32s 0
#define VER_PLATFORM_WIN32_WINDOWS 1
#define VER_PLATFORM_WIN32_NT 2
#define VER_NT_WORKSTATION 1
#define VER_NT_DOMAIN_CONTROLLER 2
#define VER_NT_SERVER 3

#define WT_EXECUTEDEFAULT 0x00000000
#define WT_EXECUTEINIOTHREAD 0x00000001
#define WT_EXECUTEINUITHREAD 0x00000002
#define WT_EXECUTEINWAITTHREAD 0x00000004
#define WT_EXECUTEONLYONCE 0x00000008
#define WT_EXECUTELONGFUNCTION 0x00000010
#define WT_EXECUTEINTIMERTHREAD 0x00000020
#define WT_EXECUTEINPERSISTENTIOTHREAD 0x00000040
#define WT_EXECUTEINPERSISTENTTHREAD 0x00000080
#define WT_TRANSFER_IMPERSONATION 0x00000100
#define WT_SET_MAX_THREADPOOL_THREADS(flags,limit) ((flags)|=(limit)<<16)
typedef VOID (NTAPI *WORKERCALLBACKFUNC)(PVOID);
#if (_WIN32_WINNT >= 0x0501)
#define ACTIVATION_CONTEXT_SECTION_ASSEMBLY_INFORMATION 1
#define ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION 2
#define ACTIVATION_CONTEXT_SECTION_WINDOW_CLASS_REDIRECTION 3
#define ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION 4
#define ACTIVATION_CONTEXT_SECTION_COM_INTERFACE_REDIRECTION 5
#define ACTIVATION_CONTEXT_SECTION_COM_TYPE_LIBRARY_REDIRECTION 6
#define ACTIVATION_CONTEXT_SECTION_COM_PROGID_REDIRECTION 7
#define ACTIVATION_CONTEXT_SECTION_CLR_SURROGATES 9
#define ACTIVATION_CONTEXT_SECTION_APPLICATION_SETTINGS 10
#define ACTIVATION_CONTEXT_SECTION_COMPATIBILITY_INFO 11
#endif /* (_WIN32_WINNT >= 0x0501) */
#define BTYPE(x) ((x)&N_BTMASK)
#define ISPTR(x) (((x)&N_TMASK)==(IMAGE_SYM_DTYPE_POINTER<<N_BTSHFT))
#define ISFCN(x) (((x)&N_TMASK)==(IMAGE_SYM_DTYPE_FUNCTION<<N_BTSHFT))
#define ISARY(x) (((x)&N_TMASK)==(IMAGE_SYM_DTYPE_ARRAY<<N_BTSHFT))
#define ISTAG(x) ((x)==IMAGE_SYM_CLASS_STRUCT_TAG||(x)==IMAGE_SYM_CLASS_UNION_TAG||(x)==IMAGE_SYM_CLASS_ENUM_TAG)
#define INCREF(x) ((((x)&~N_BTMASK)<<N_TSHIFT)|(IMAGE_SYM_DTYPE_POINTER<<N_BTSHFT)|((x)&N_BTMASK))
#define DECREF(x) ((((x)>>N_TSHIFT)&~N_BTMASK)|((x)&N_BTMASK))
#define TLS_MINIMUM_AVAILABLE 64
#define FLS_MAXIMUM_AVAILABLE 128
#define REPARSE_GUID_DATA_BUFFER_HEADER_SIZE   FIELD_OFFSET(REPARSE_GUID_DATA_BUFFER, GenericReparseBuffer)
#define MAXIMUM_REPARSE_DATA_BUFFER_SIZE 16384
#define IO_REPARSE_TAG_RESERVED_ZERO 0
#define IO_REPARSE_TAG_RESERVED_ONE 1
#define IO_REPARSE_TAG_RESERVED_RANGE IO_REPARSE_TAG_RESERVED_ONE
#define IsReparseTagMicrosoft(x) ((x)&0x80000000)
#define IsReparseTagHighLatency(x) ((x)&0x40000000)
#define IsReparseTagNameSurrogate(x) ((x)&0x20000000)
#define IO_REPARSE_TAG_VALID_VALUES 0xE000FFFF
#define IsReparseTagValid(x) (!((x)&~IO_REPARSE_TAG_VALID_VALUES)&&((x)>IO_REPARSE_TAG_RESERVED_RANGE))
#define IO_REPARSE_TAG_SYMBOLIC_LINK IO_REPARSE_TAG_RESERVED_ZERO
#define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003
#define IO_REPARSE_TAG_SYMLINK 0xA000000CL

#define RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO 0x01000000

#ifndef RC_INVOKED

#ifdef _GUID_DEFINED
# warning _GUID_DEFINED is deprecated, use GUID_DEFINED instead
#endif

#if ! (defined _GUID_DEFINED || defined GUID_DEFINED) /* also defined in basetyps.h */
#define GUID_DEFINED
typedef struct _GUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[8];
} GUID, *REFGUID, *LPGUID;
#endif /* GUID_DEFINED */

typedef enum _ACL_INFORMATION_CLASS {
  AclRevisionInformation = 1,
  AclSizeInformation
} ACL_INFORMATION_CLASS;

typedef struct _ACL_REVISION_INFORMATION {
  DWORD AclRevision;
} ACL_REVISION_INFORMATION, *PACL_REVISION_INFORMATION;

typedef struct _ACL_SIZE_INFORMATION {
  DWORD AceCount;
  DWORD AclBytesInUse;
  DWORD AclBytesFree;
} ACL_SIZE_INFORMATION, *PACL_SIZE_INFORMATION;

#ifndef _LDT_ENTRY_DEFINED
#define _LDT_ENTRY_DEFINED

typedef struct _LDT_ENTRY {
  WORD LimitLow;
  WORD BaseLow;
  union {
    struct {
      BYTE BaseMid;
      BYTE Flags1;
      BYTE Flags2;
      BYTE BaseHi;
    } Bytes;
    struct {
      DWORD BaseMid:8;
      DWORD Type:5;
      DWORD Dpl:2;
      DWORD Pres:1;
      DWORD LimitHi:4;
      DWORD Sys:1;
      DWORD Reserved_0:1;
      DWORD Default_Big:1;
      DWORD Granularity:1;
      DWORD BaseHi:8;
    } Bits;
  } HighWord;
} LDT_ENTRY, *PLDT_ENTRY, *LPLDT_ENTRY;

#endif /* _LDT_ENTRY_DEFINED */

/* FIXME: add more machines */
#if defined(_X86_)
#define SIZE_OF_80387_REGISTERS    80
#define CONTEXT_i386    0x10000
#define CONTEXT_i486    0x10000
#define CONTEXT_CONTROL    (CONTEXT_i386|0x00000001L)
#define CONTEXT_INTEGER    (CONTEXT_i386|0x00000002L)
#define CONTEXT_SEGMENTS    (CONTEXT_i386|0x00000004L)
#define CONTEXT_FLOATING_POINT    (CONTEXT_i386|0x00000008L)
#define CONTEXT_DEBUG_REGISTERS    (CONTEXT_i386|0x00000010L)
#define CONTEXT_EXTENDED_REGISTERS (CONTEXT_i386|0x00000020L)
#define CONTEXT_FULL    (CONTEXT_CONTROL|CONTEXT_INTEGER|CONTEXT_SEGMENTS)
#define CONTEXT_ALL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | \
                     CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | \
                     CONTEXT_EXTENDED_REGISTERS)
#define MAXIMUM_SUPPORTED_EXTENSION  512

#define EXCEPTION_READ_FAULT    0
#define EXCEPTION_WRITE_FAULT   1
#define EXCEPTION_EXECUTE_FAULT 8

typedef struct _FLOATING_SAVE_AREA {
  DWORD ControlWord;
  DWORD StatusWord;
  DWORD TagWord;
  DWORD ErrorOffset;
  DWORD ErrorSelector;
  DWORD DataOffset;
  DWORD DataSelector;
  BYTE RegisterArea[SIZE_OF_80387_REGISTERS];
  DWORD Cr0NpxState;
} FLOATING_SAVE_AREA, *PFLOATING_SAVE_AREA;

typedef struct _CONTEXT {
  DWORD ContextFlags;
  DWORD Dr0;
  DWORD Dr1;
  DWORD Dr2;
  DWORD Dr3;
  DWORD Dr6;
  DWORD Dr7;
  FLOATING_SAVE_AREA FloatSave;
  DWORD SegGs;
  DWORD SegFs;
  DWORD SegEs;
  DWORD SegDs;
  DWORD Edi;
  DWORD Esi;
  DWORD Ebx;
  DWORD Edx;
  DWORD Ecx;
  DWORD Eax;
  DWORD Ebp;
  DWORD Eip;
  DWORD SegCs;
  DWORD EFlags;
  DWORD Esp;
  DWORD SegSs;
  BYTE ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
} CONTEXT;
#elif defined(_AMD64_)

#define CONTEXT_AMD64 0x100000

#if !defined(RC_INVOKED)
#define CONTEXT_CONTROL (CONTEXT_AMD64 | 0x1L)
#define CONTEXT_INTEGER (CONTEXT_AMD64 | 0x2L)
#define CONTEXT_SEGMENTS (CONTEXT_AMD64 | 0x4L)
#define CONTEXT_FLOATING_POINT (CONTEXT_AMD64 | 0x8L)
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_AMD64 | 0x10L)

#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
#define CONTEXT_ALL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)

#define CONTEXT_EXCEPTION_ACTIVE 0x8000000
#define CONTEXT_SERVICE_ACTIVE 0x10000000
#define CONTEXT_EXCEPTION_REQUEST 0x40000000
#define CONTEXT_EXCEPTION_REPORTING 0x80000000
#endif

#define INITIAL_MXCSR 0x1f80
#define INITIAL_FPCSR 0x027f
#define EXCEPTION_READ_FAULT    0
#define EXCEPTION_WRITE_FAULT   1
#define EXCEPTION_EXECUTE_FAULT 8

typedef struct DECLSPEC_ALIGN(16) _M128A {
    ULONGLONG Low;
    LONGLONG High;
} M128A, *PM128A;

typedef struct _XMM_SAVE_AREA32 {
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
} XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;

typedef struct DECLSPEC_ALIGN(16) _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;

    /* Control flags */
    DWORD ContextFlags;
    DWORD MxCsr;

    /* Segment */
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;

    /* Debug */
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;

    /* Integer */
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;

    /* Counter */
    DWORD64 Rip;

   /* Floating point */
   union {
       XMM_SAVE_AREA32 FltSave;
       struct {
           M128A Header[2];
           M128A Legacy[8];
           M128A Xmm0;
           M128A Xmm1;
           M128A Xmm2;
           M128A Xmm3;
           M128A Xmm4;
           M128A Xmm5;
           M128A Xmm6;
           M128A Xmm7;
           M128A Xmm8;
           M128A Xmm9;
           M128A Xmm10;
           M128A Xmm11;
           M128A Xmm12;
           M128A Xmm13;
           M128A Xmm14;
           M128A Xmm15;
      } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

     /* Vector */
    M128A VectorRegister[26];
    DWORD64 VectorControl;

    /* Debug control */
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
} CONTEXT;


typedef struct _KNONVOLATILE_CONTEXT_POINTERS {
    union {
        PM128A FloatingContext[16];
        struct {
            PM128A Xmm0;
            PM128A Xmm1;
            PM128A Xmm2;
            PM128A Xmm3;
            PM128A Xmm4;
            PM128A Xmm5;
            PM128A Xmm6;
            PM128A Xmm7;
            PM128A Xmm8;
            PM128A Xmm9;
            PM128A Xmm10;
            PM128A Xmm11;
            PM128A Xmm12;
            PM128A Xmm13;
            PM128A Xmm14;
            PM128A Xmm15;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    union {
        PULONG64 IntegerContext[16];
        struct {
            PULONG64 Rax;
            PULONG64 Rcx;
            PULONG64 Rdx;
            PULONG64 Rbx;
            PULONG64 Rsp;
            PULONG64 Rbp;
            PULONG64 Rsi;
            PULONG64 Rdi;
            PULONG64 R8;
            PULONG64 R9;
            PULONG64 R10;
            PULONG64 R11;
            PULONG64 R12;
            PULONG64 R13;
            PULONG64 R14;
            PULONG64 R15;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME2;
} KNONVOLATILE_CONTEXT_POINTERS, *PKNONVOLATILE_CONTEXT_POINTERS;

#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2
#define UNW_FLAG_CHAININFO 0x4
#define UNW_FLAG_NO_EPILOGUE  0x80000000UL

#define RUNTIME_FUNCTION_INDIRECT 0x1

typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
} RUNTIME_FUNCTION,*PRUNTIME_FUNCTION;

#define UNWIND_HISTORY_TABLE_SIZE 12

typedef struct _UNWIND_HISTORY_TABLE_ENTRY
{
    DWORD64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
} UNWIND_HISTORY_TABLE_ENTRY, *PUNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE
{
    DWORD Count;
    BYTE  LocalHint;
    BYTE  GlobalHint;
    BYTE  Search;
    BYTE  Once;
    ULONG64 LowAddress;
    ULONG64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[UNWIND_HISTORY_TABLE_SIZE];
} UNWIND_HISTORY_TABLE, *PUNWIND_HISTORY_TABLE;

typedef
_Function_class_(GET_RUNTIME_FUNCTION_CALLBACK)
PRUNTIME_FUNCTION
GET_RUNTIME_FUNCTION_CALLBACK(
    _In_ DWORD64 ControlPc,
    _In_opt_ PVOID Context);
typedef GET_RUNTIME_FUNCTION_CALLBACK *PGET_RUNTIME_FUNCTION_CALLBACK;

typedef
_Function_class_(OUT_OF_PROCESS_FUNCTION_TABLE_CALLBACK)
DWORD
OUT_OF_PROCESS_FUNCTION_TABLE_CALLBACK(
    _In_ HANDLE Process,
    _In_ PVOID TableAddress,
    _Out_ PDWORD Entries,
    _Out_ PRUNTIME_FUNCTION* Functions);
typedef OUT_OF_PROCESS_FUNCTION_TABLE_CALLBACK *POUT_OF_PROCESS_FUNCTION_TABLE_CALLBACK;

struct _EXCEPTION_POINTERS;
typedef
LONG
(*PEXCEPTION_FILTER) (
    struct _EXCEPTION_POINTERS *ExceptionPointers,
    PVOID EstablisherFrame);

typedef
VOID
(*PTERMINATION_HANDLER) (
    BOOLEAN AbnormalTermination,
    PVOID EstablisherFrame);

typedef struct _DISPATCHER_CONTEXT
{
    ULONG64 ControlPc;
    ULONG64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
    ULONG64 EstablisherFrame;
    ULONG64 TargetIp;
    struct _CONTEXT *ContextRecord;
    PEXCEPTION_ROUTINE LanguageHandler;
    PVOID HandlerData;
    PUNWIND_HISTORY_TABLE HistoryTable;
    ULONG ScopeIndex;
    ULONG Fill0;
} DISPATCHER_CONTEXT, *PDISPATCHER_CONTEXT;

typedef struct _SCOPE_TABLE_AMD64
{
    DWORD Count;
    struct
    {
        DWORD BeginAddress;
        DWORD EndAddress;
        DWORD HandlerAddress;
        DWORD JumpTarget;
    } ScopeRecord[1];
} SCOPE_TABLE_AMD64, *PSCOPE_TABLE_AMD64;
typedef SCOPE_TABLE_AMD64 SCOPE_TABLE, *PSCOPE_TABLE;

#define OUT_OF_PROCESS_FUNCTION_TABLE_CALLBACK_EXPORT_NAME "OutOfProcessFunctionTableCallback"

NTSYSAPI
VOID
__cdecl
RtlRestoreContext(struct _CONTEXT *ContextRecord,
                  struct _EXCEPTION_RECORD *ExceptionRecord);

NTSYSAPI
BOOLEAN
__cdecl
RtlAddFunctionTable(PRUNTIME_FUNCTION FunctionTable,
                    DWORD EntryCount,
                    DWORD64 BaseAddress);

NTSYSAPI
BOOLEAN
__cdecl
RtlInstallFunctionTableCallback(DWORD64 TableIdentifier,
                                DWORD64 BaseAddress,
                                DWORD Length,
                                PGET_RUNTIME_FUNCTION_CALLBACK Callback,
                                PVOID Context,
                                PCWSTR OutOfProcessCallbackDll);

NTSYSAPI
BOOLEAN
__cdecl
RtlDeleteFunctionTable(PRUNTIME_FUNCTION FunctionTable);

NTSYSAPI
PRUNTIME_FUNCTION
NTAPI
RtlLookupFunctionEntry(
    _In_ DWORD64 ControlPc,
    _Out_ PDWORD64 ImageBase,
    _Inout_opt_ PUNWIND_HISTORY_TABLE HistoryTable);

NTSYSAPI
PEXCEPTION_ROUTINE
NTAPI
RtlVirtualUnwind(
    _In_ DWORD HandlerType,
    _In_ DWORD64 ImageBase,
    _In_ DWORD64 ControlPc,
    _In_ PRUNTIME_FUNCTION FunctionEntry,
    _Inout_ struct _CONTEXT *ContextRecord,
    _Out_ PVOID *HandlerData,
    _Out_ PDWORD64 EstablisherFrame,
    _Inout_opt_ PKNONVOLATILE_CONTEXT_POINTERS ContextPointers);

NTSYSAPI
VOID
NTAPI
RtlUnwindEx(
    _In_opt_ PVOID TargetFrame,
    _In_opt_ PVOID TargetIp,
    _In_opt_ struct _EXCEPTION_RECORD *ExceptionRecord,
    _In_ PVOID ReturnValue,
    _In_ struct _CONTEXT *ContextRecord,
    _In_opt_ PUNWIND_HISTORY_TABLE HistoryTable);

#elif defined(_PPC_)
#define CONTEXT_CONTROL    1L
#define CONTEXT_FLOATING_POINT    2L
#define CONTEXT_INTEGER    4L
#define CONTEXT_DEBUG_REGISTERS    8L
#define CONTEXT_FULL (CONTEXT_CONTROL|CONTEXT_FLOATING_POINT|CONTEXT_INTEGER)
typedef struct _FLOATING_SAVE_AREA
{
    double Fpr0;
    double Fpr1;
    double Fpr2;
    double Fpr3;
    double Fpr4;
    double Fpr5;
    double Fpr6;
    double Fpr7;
    double Fpr8;
    double Fpr9;
    double Fpr10;
    double Fpr11;
    double Fpr12;
    double Fpr13;
    double Fpr14;
    double Fpr15;
    double Fpr16;
    double Fpr17;
    double Fpr18;
    double Fpr19;
    double Fpr20;
    double Fpr21;
    double Fpr22;
    double Fpr23;
    double Fpr24;
    double Fpr25;
    double Fpr26;
    double Fpr27;
    double Fpr28;
    double Fpr29;
    double Fpr30;
    double Fpr31;
    double Fpscr;
} FLOATING_SAVE_AREA;

typedef struct _CONTEXT {
        FLOATING_SAVE_AREA FloatSave;
    DWORD Gpr0;
    DWORD Gpr1;
    DWORD Gpr2;
    DWORD Gpr3;
    DWORD Gpr4;
    DWORD Gpr5;
    DWORD Gpr6;
    DWORD Gpr7;
    DWORD Gpr8;
    DWORD Gpr9;
    DWORD Gpr10;
    DWORD Gpr11;
    DWORD Gpr12;
    DWORD Gpr13;
    DWORD Gpr14;
    DWORD Gpr15;
    DWORD Gpr16;
    DWORD Gpr17;
    DWORD Gpr18;
    DWORD Gpr19;
    DWORD Gpr20;
    DWORD Gpr21;
    DWORD Gpr22;
    DWORD Gpr23;
    DWORD Gpr24;
    DWORD Gpr25;
    DWORD Gpr26;
    DWORD Gpr27;
    DWORD Gpr28;
    DWORD Gpr29;
    DWORD Gpr30;
    DWORD Gpr31;
    DWORD Cr;
    DWORD Xer;
    DWORD Msr;
    DWORD Iar;
    DWORD Lr;
    DWORD Ctr;
    DWORD ContextFlags;
    DWORD Fill[3];
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr4;
    DWORD Dr5;
    DWORD Dr6;
    DWORD Dr7;
} CONTEXT;
#elif defined(_ALPHA_)
#define CONTEXT_ALPHA    0x20000
#define CONTEXT_CONTROL    (CONTEXT_ALPHA|1L)
#define CONTEXT_FLOATING_POINT    (CONTEXT_ALPHA|2L)
#define CONTEXT_INTEGER    (CONTEXT_ALPHA|4L)
#define CONTEXT_FULL    (CONTEXT_CONTROL|CONTEXT_FLOATING_POINT|CONTEXT_INTEGER)
typedef struct _CONTEXT {
    ULONGLONG FltF0;
    ULONGLONG FltF1;
    ULONGLONG FltF2;
    ULONGLONG FltF3;
    ULONGLONG FltF4;
    ULONGLONG FltF5;
    ULONGLONG FltF6;
    ULONGLONG FltF7;
    ULONGLONG FltF8;
    ULONGLONG FltF9;
    ULONGLONG FltF10;
    ULONGLONG FltF11;
    ULONGLONG FltF12;
    ULONGLONG FltF13;
    ULONGLONG FltF14;
    ULONGLONG FltF15;
    ULONGLONG FltF16;
    ULONGLONG FltF17;
    ULONGLONG FltF18;
    ULONGLONG FltF19;
    ULONGLONG FltF20;
    ULONGLONG FltF21;
    ULONGLONG FltF22;
    ULONGLONG FltF23;
    ULONGLONG FltF24;
    ULONGLONG FltF25;
    ULONGLONG FltF26;
    ULONGLONG FltF27;
    ULONGLONG FltF28;
    ULONGLONG FltF29;
    ULONGLONG FltF30;
    ULONGLONG FltF31;
    ULONGLONG IntV0;
    ULONGLONG IntT0;
    ULONGLONG IntT1;
    ULONGLONG IntT2;
    ULONGLONG IntT3;
    ULONGLONG IntT4;
    ULONGLONG IntT5;
    ULONGLONG IntT6;
    ULONGLONG IntT7;
    ULONGLONG IntS0;
    ULONGLONG IntS1;
    ULONGLONG IntS2;
    ULONGLONG IntS3;
    ULONGLONG IntS4;
    ULONGLONG IntS5;
    ULONGLONG IntFp;
    ULONGLONG IntA0;
    ULONGLONG IntA1;
    ULONGLONG IntA2;
    ULONGLONG IntA3;
    ULONGLONG IntA4;
    ULONGLONG IntA5;
    ULONGLONG IntT8;
    ULONGLONG IntT9;
    ULONGLONG IntT10;
    ULONGLONG IntT11;
    ULONGLONG IntRa;
    ULONGLONG IntT12;
    ULONGLONG IntAt;
    ULONGLONG IntGp;
    ULONGLONG IntSp;
    ULONGLONG IntZero;
    ULONGLONG Fpcr;
    ULONGLONG SoftFpcr;
    ULONGLONG Fir;
    DWORD Psr;
    DWORD ContextFlags;
    DWORD Fill[4];
} CONTEXT;
#elif defined(_SH_)

/* These are the debug or break registers on the SH3 */
typedef struct _DEBUG_REGISTERS {
    DWORD  BarA;
    UCHAR  BasrA;
    UCHAR  BamrA;
    USHORT BbrA;
    DWORD  BarB;
    UCHAR  BasrB;
    UCHAR  BamrB;
    USHORT BbrB;
    DWORD  BdrB;
    DWORD  BdmrB;
    USHORT Brcr;
    USHORT Align;
} DEBUG_REGISTERS, *PDEBUG_REGISTERS;

/* The following flags control the contents of the CONTEXT structure. */

#define CONTEXT_SH3        0x00000040
#define CONTEXT_SH4        0x000000c0    /* CONTEXT_SH3 | 0x80 - must contain the SH3 bits */

#ifdef SH3
#define CONTEXT_CONTROL         (CONTEXT_SH3 | 0x00000001L)
#define CONTEXT_INTEGER         (CONTEXT_SH3 | 0x00000002L)
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_SH3 | 0x00000008L)
#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS)
#else    /* SH4 */
#define CONTEXT_CONTROL         (CONTEXT_SH4 | 0x00000001L)
#define CONTEXT_INTEGER         (CONTEXT_SH4 | 0x00000002L)
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_SH4 | 0x00000008L)
#define CONTEXT_FLOATING_POINT  (CONTEXT_SH4 | 0x00000004L)
#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS | CONTEXT_FLOATING_POINT)
#endif

/* Context Frame */

/*  This frame is used to store a limited processor context into the */
/* Thread structure for CPUs which have no floating point support. */

typedef struct _CONTEXT {
    /* The flags values within this flag control the contents of */
    /* a CONTEXT record. */

    /* If the context record is used as an input parameter, then */
    /* for each portion of the context record controlled by a flag */
    /* whose value is set, it is assumed that that portion of the */
    /* context record contains valid context. If the context record */
    /* is being used to modify a thread's context, then only that */
    /* portion of the threads context will be modified. */

    /* If the context record is used as an IN OUT parameter to capture */
    /* the context of a thread, then only those portions of the thread's */
    /* context corresponding to set flags will be returned. */

    /* The context record is never used as an OUT only parameter. */


    DWORD ContextFlags;

    /* This section is specified/returned if the ContextFlags word contains */
    /* the flag CONTEXT_INTEGER. */

    /* N.B. The registers RA and R15 are defined in this section, but are */
    /*  considered part of the control context rather than part of the integer */
    /*  context. */

    DWORD PR;
    DWORD MACH;
    DWORD MACL;
    DWORD GBR;
    DWORD R0;
    DWORD R1;
    DWORD R2;
    DWORD R3;
    DWORD R4;
    DWORD R5;
    DWORD R6;
    DWORD R7;
    DWORD R8;
    DWORD R9;
    DWORD R10;
    DWORD R11;
    DWORD R12;
    DWORD R13;
    DWORD R14;
    DWORD R15;

    /* This section is specified/returned if the ContextFlags word contains */
    /* the flag CONTEXT_CONTROL. */

    /* N.B. The registers r15 and ra are defined in the integer section, */
    /*   but are considered part of the control context rather than part of */
    /*   the integer context. */

    DWORD Fir;
    DWORD Psr;

#if !defined(SH3e) && !defined(SH4)
    DWORD    OldStuff[2];
    DEBUG_REGISTERS DebugRegisters;
#else
    DWORD    Fpscr;
    DWORD    Fpul;
    DWORD    FRegs[16];
#if defined(SH4)
    DWORD    xFRegs[16];
#endif
#endif
} CONTEXT;

#elif defined(_MIPS_)

/* The following flags control the contents of the CONTEXT structure. */

#define CONTEXT_R4000   0x00010000    /* r4000 context */

#define CONTEXT_CONTROL         (CONTEXT_R4000 | 0x00000001L)
#define CONTEXT_FLOATING_POINT  (CONTEXT_R4000 | 0x00000002L)
#define CONTEXT_INTEGER         (CONTEXT_R4000 | 0x00000004L)

#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_FLOATING_POINT | CONTEXT_INTEGER)

/* Context Frame */

/*  N.B. This frame must be exactly a multiple of 16 bytes in length. */

/*  This frame has a several purposes: 1) it is used as an argument to */
/*  NtContinue, 2) it is used to constuct a call frame for APC delivery, */
/*  3) it is used to construct a call frame for exception dispatching */
/*  in user mode, and 4) it is used in the user level thread creation */
/*  routines. */

/*  The layout of the record conforms to a standard call frame. */


typedef struct _CONTEXT {

    /* This section is always present and is used as an argument build */
    /* area. */

    DWORD Argument[4];

    /* This section is specified/returned if the ContextFlags word contains */
    /* the flag CONTEXT_FLOATING_POINT. */

    DWORD FltF0;
    DWORD FltF1;
    DWORD FltF2;
    DWORD FltF3;
    DWORD FltF4;
    DWORD FltF5;
    DWORD FltF6;
    DWORD FltF7;
    DWORD FltF8;
    DWORD FltF9;
    DWORD FltF10;
    DWORD FltF11;
    DWORD FltF12;
    DWORD FltF13;
    DWORD FltF14;
    DWORD FltF15;
    DWORD FltF16;
    DWORD FltF17;
    DWORD FltF18;
    DWORD FltF19;
    DWORD FltF20;
    DWORD FltF21;
    DWORD FltF22;
    DWORD FltF23;
    DWORD FltF24;
    DWORD FltF25;
    DWORD FltF26;
    DWORD FltF27;
    DWORD FltF28;
    DWORD FltF29;
    DWORD FltF30;
    DWORD FltF31;

    /* This section is specified/returned if the ContextFlags word contains */
    /* the flag CONTEXT_INTEGER. */

    /* N.B. The registers gp, sp, and ra are defined in this section, but are */
    /*  considered part of the control context rather than part of the integer */
    /*  context. */

    /* N.B. Register zero is not stored in the frame. */

    DWORD IntZero;
    DWORD IntAt;
    DWORD IntV0;
    DWORD IntV1;
    DWORD IntA0;
    DWORD IntA1;
    DWORD IntA2;
    DWORD IntA3;
    DWORD IntT0;
    DWORD IntT1;
    DWORD IntT2;
    DWORD IntT3;
    DWORD IntT4;
    DWORD IntT5;
    DWORD IntT6;
    DWORD IntT7;
    DWORD IntS0;
    DWORD IntS1;
    DWORD IntS2;
    DWORD IntS3;
    DWORD IntS4;
    DWORD IntS5;
    DWORD IntS6;
    DWORD IntS7;
    DWORD IntT8;
    DWORD IntT9;
    DWORD IntK0;
    DWORD IntK1;
    DWORD IntGp;
    DWORD IntSp;
    DWORD IntS8;
    DWORD IntRa;
    DWORD IntLo;
    DWORD IntHi;

    /* This section is specified/returned if the ContextFlags word contains */
    /* the flag CONTEXT_FLOATING_POINT. */

    DWORD Fsr;

    /* This section is specified/returned if the ContextFlags word contains */
    /* the flag CONTEXT_CONTROL. */

    /* N.B. The registers gp, sp, and ra are defined in the integer section, */
    /*   but are considered part of the control context rather than part of */
    /*   the integer context. */

    DWORD Fir;
    DWORD Psr;

    /* The flags values within this flag control the contents of */
    /* a CONTEXT record. */

    /* If the context record is used as an input parameter, then */
    /* for each portion of the context record controlled by a flag */
    /* whose value is set, it is assumed that that portion of the */
    /* context record contains valid context. If the context record */
    /* is being used to modify a thread's context, then only that */
    /* portion of the threads context will be modified. */

    /* If the context record is used as an IN OUT parameter to capture */
    /* the context of a thread, then only those portions of the thread's */
    /* context corresponding to set flags will be returned. */

    /* The context record is never used as an OUT only parameter. */

    DWORD ContextFlags;

    DWORD Fill[2];

} CONTEXT;
#elif defined(_ARM_)

#ifndef PAGE_SIZE
#define PAGE_SIZE                         0x1000 // FIXME: This should probably go elsewhere
#endif

/* The following flags control the contents of the CONTEXT structure. */

#define CONTEXT_ARM             0x200000L
#define CONTEXT_CONTROL         (CONTEXT_ARM | 0x00000001L)
#define CONTEXT_INTEGER         (CONTEXT_ARM | 0x00000002L)
#define CONTEXT_FLOATING_POINT  (CONTEXT_ARM | 0x00000004L)
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_ARM | 0x00000008L)
#define CONTEXT_FULL            (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)

#define EXCEPTION_READ_FAULT    0
#define EXCEPTION_WRITE_FAULT   1
#define EXCEPTION_EXECUTE_FAULT 8

typedef struct _NEON128
{
    ULONGLONG Low;
    LONGLONG High;
} NEON128, *PNEON128;

#define ARM_MAX_BREAKPOINTS 8
#define ARM_MAX_WATCHPOINTS 1

typedef struct _CONTEXT
{
    /* The flags values within this flag control the contents of
       a CONTEXT record.

       If the context record is used as an input parameter, then
       for each portion of the context record controlled by a flag
       whose value is set, it is assumed that that portion of the
       context record contains valid context. If the context record
       is being used to modify a thread's context, then only that
       portion of the threads context will be modified.

       If the context record is used as an IN OUT parameter to capture
       the context of a thread, then only those portions of the thread's
       context corresponding to set flags will be returned.

       The context record is never used as an OUT only parameter. */
    DWORD ContextFlags;

    /* This section is specified/returned if the ContextFlags word contains
       the flag CONTEXT_INTEGER. */
    DWORD R0;
    DWORD R1;
    DWORD R2;
    DWORD R3;
    DWORD R4;
    DWORD R5;
    DWORD R6;
    DWORD R7;
    DWORD R8;
    DWORD R9;
    DWORD R10;
    DWORD R11;
    DWORD R12;

    DWORD Sp;
    DWORD Lr;
    DWORD Pc;
    DWORD Cpsr;

    /* Floating Point/NEON Registers */
    DWORD Fpscr;
    DWORD Padding;
    union
    {
        NEON128 Q[16];
        ULONGLONG D[32];
        DWORD S[32];
    } DUMMYUNIONNAME;

    /* Debug registers */
    DWORD Bvr[ARM_MAX_BREAKPOINTS];
    DWORD Bcr[ARM_MAX_BREAKPOINTS];
    DWORD Wvr[ARM_MAX_WATCHPOINTS];
    DWORD Wcr[ARM_MAX_WATCHPOINTS];

    DWORD Padding2[2];
} CONTEXT, *PCONTEXT;

typedef struct _IMAGE_ARM_RUNTIME_FUNCTION_ENTRY
{
    DWORD BeginAddress;
    union
    {
        DWORD UnwindData;
        struct
        {
            DWORD Flag : 2;
            DWORD FunctionLength : 11;
            DWORD Ret : 2;
            DWORD H : 1;
            DWORD Reg : 3;
            DWORD R : 1;
            DWORD L : 1;
            DWORD C : 1;
            DWORD StackAdjust : 10;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} IMAGE_ARM_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ARM_RUNTIME_FUNCTION_ENTRY;
typedef IMAGE_ARM_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

typedef struct _SCOPE_TABLE_ARM
{
    DWORD Count;
    struct
    {
        DWORD BeginAddress;
        DWORD EndAddress;
        DWORD HandlerAddress;
        DWORD JumpTarget;
    } ScopeRecord[1];
} SCOPE_TABLE_ARM, *PSCOPE_TABLE_ARM;
typedef SCOPE_TABLE_ARM SCOPE_TABLE, *PSCOPE_TABLE;

typedef struct _DISPATCHER_CONTEXT
{
    DWORD ControlPc;
    DWORD ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
    DWORD EstablisherFrame;
    DWORD TargetPc;
    PCONTEXT ContextRecord;
    PEXCEPTION_ROUTINE LanguageHandler;
    PVOID HandlerData;
    struct _UNWIND_HISTORY_TABLE *HistoryTable;
    DWORD ScopeIndex;
    BOOLEAN ControlPcIsUnwound;
    PBYTE  NonVolatileRegisters;
    DWORD Reserved;
} DISPATCHER_CONTEXT, *PDISPATCHER_CONTEXT;

#elif defined(_ARM64_)

#define CONTEXT_ARM64   0x00400000L
#define CONTEXT_CONTROL (CONTEXT_ARM64 | 0x1L)
#define CONTEXT_INTEGER (CONTEXT_ARM64 | 0x2L)
#define CONTEXT_FLOATING_POINT  (CONTEXT_ARM64 | 0x4L)
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_ARM64 | 0x8L)
#define CONTEXT_X18 (CONTEXT_ARM64 | 0x10L)
#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)


#define EXCEPTION_READ_FAULT    0
#define EXCEPTION_WRITE_FAULT   1
#define EXCEPTION_EXECUTE_FAULT 8

typedef union NEON128 {
    struct {
        ULONGLONG Low;
        LONGLONG High;
    } DUMMYSTRUCTNAME;
    double D[2];
    float S[4];
    WORD   H[8];
    BYTE  B[16];
} NEON128, *PNEON128;

#define ARM64_MAX_BREAKPOINTS 8
#define ARM64_MAX_WATCHPOINTS 2

typedef struct _CONTEXT {

    //
    // Control flags.
    //

    DWORD ContextFlags;

    //
    // Integer registers
    //

    DWORD Cpsr;
    union {
        struct {
            DWORD64 X0;
            DWORD64 X1;
            DWORD64 X2;
            DWORD64 X3;
            DWORD64 X4;
            DWORD64 X5;
            DWORD64 X6;
            DWORD64 X7;
            DWORD64 X8;
            DWORD64 X9;
            DWORD64 X10;
            DWORD64 X11;
            DWORD64 X12;
            DWORD64 X13;
            DWORD64 X14;
            DWORD64 X15;
            DWORD64 X16;
            DWORD64 X17;
            DWORD64 X18;
            DWORD64 X19;
            DWORD64 X20;
            DWORD64 X21;
            DWORD64 X22;
            DWORD64 X23;
            DWORD64 X24;
            DWORD64 X25;
            DWORD64 X26;
            DWORD64 X27;
            DWORD64 X28;
            DWORD64 Fp;
            DWORD64 Lr;
        } DUMMYSTRUCTNAME;
        DWORD64 X[31];
    } DUMMYUNIONNAME;

    DWORD64 Sp;
    DWORD64 Pc;

    //
    // Floating Point/NEON Registers
    //

    NEON128 V[32];
    DWORD Fpcr;
    DWORD Fpsr;

    //
    // Debug registers
    //

    DWORD Bcr[ARM64_MAX_BREAKPOINTS];
    DWORD64 Bvr[ARM64_MAX_BREAKPOINTS];
    DWORD Wcr[ARM64_MAX_WATCHPOINTS];
    DWORD64 Wvr[ARM64_MAX_WATCHPOINTS];

} _CONTEXT, *P_CONTEXT;
typedef _CONTEXT CONTEXT, *PCONTEXT;

typedef struct _IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY {
    DWORD BeginAddress;
    union {
        DWORD UnwindData;
        struct {
            DWORD Flag : 2;
            DWORD FunctionLength : 11;
            DWORD RegF : 3;
            DWORD RegI : 4;
            DWORD H : 1;
            DWORD CR : 2;
            DWORD FrameSize : 9;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY, * PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY;
typedef struct _IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

typedef struct _SCOPE_TABLE_ARM64 {
    DWORD Count;
    struct
    {
        DWORD BeginAddress;
        DWORD EndAddress;
        DWORD HandlerAddress;
        DWORD JumpTarget;
    } ScopeRecord[1];
} SCOPE_TABLE_ARM64, *PSCOPE_TABLE_ARM64;
typedef SCOPE_TABLE_ARM64 SCOPE_TABLE, *PSCOPE_TABLE;

typedef struct _DISPATCHER_CONTEXT {
    ULONG_PTR ControlPc;
    ULONG_PTR ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
    ULONG_PTR EstablisherFrame;
    ULONG_PTR TargetPc;
    PCONTEXT ContextRecord;
    PEXCEPTION_ROUTINE LanguageHandler;
    PVOID HandlerData;
    struct _UNWIND_HISTORY_TABLE *HistoryTable;
    DWORD ScopeIndex;
    BOOLEAN ControlPcIsUnwound;
    PBYTE  NonVolatileRegisters;
} DISPATCHER_CONTEXT, *PDISPATCHER_CONTEXT;
#else
#error "undefined processor type"
#endif
typedef CONTEXT *PCONTEXT;

/* The WoW64 context */
#define WOW64_CONTEXT_i386 0x00010000
#define WOW64_CONTEXT_i486 0x00010000
#define WOW64_CONTEXT_CONTROL (WOW64_CONTEXT_i386 | __MSABI_LONG(0x00000001))
#define WOW64_CONTEXT_INTEGER (WOW64_CONTEXT_i386 | __MSABI_LONG(0x00000002))
#define WOW64_CONTEXT_SEGMENTS (WOW64_CONTEXT_i386 | __MSABI_LONG(0x00000004))
#define WOW64_CONTEXT_FLOATING_POINT (WOW64_CONTEXT_i386 | __MSABI_LONG(0x00000008))
#define WOW64_CONTEXT_DEBUG_REGISTERS (WOW64_CONTEXT_i386 | __MSABI_LONG(0x00000010))
#define WOW64_CONTEXT_EXTENDED_REGISTERS (WOW64_CONTEXT_i386 | __MSABI_LONG(0x00000020))
#define WOW64_CONTEXT_FULL (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS)
#define WOW64_CONTEXT_ALL (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | \
                           WOW64_CONTEXT_SEGMENTS | WOW64_CONTEXT_FLOATING_POINT | \
                           WOW64_CONTEXT_DEBUG_REGISTERS | WOW64_CONTEXT_EXTENDED_REGISTERS)

#define WOW64_CONTEXT_XSTATE (WOW64_CONTEXT_i386 | __MSABI_LONG(0x00000040))

#define WOW64_CONTEXT_EXCEPTION_ACTIVE      0x08000000
#define WOW64_CONTEXT_SERVICE_ACTIVE        0x10000000
#define WOW64_CONTEXT_EXCEPTION_REQUEST     0x40000000
#define WOW64_CONTEXT_EXCEPTION_REPORTING   0x80000000

#define WOW64_SIZE_OF_80387_REGISTERS 80
#define WOW64_MAXIMUM_SUPPORTED_EXTENSION 512

typedef struct _WOW64_FLOATING_SAVE_AREA
{
    DWORD   ControlWord;
    DWORD   StatusWord;
    DWORD   TagWord;
    DWORD   ErrorOffset;
    DWORD   ErrorSelector;
    DWORD   DataOffset;
    DWORD   DataSelector;
    BYTE    RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
    DWORD   Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA, *PWOW64_FLOATING_SAVE_AREA;

#include "pshpack4.h"
typedef struct _WOW64_CONTEXT
{
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    WOW64_FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];
} WOW64_CONTEXT, *PWOW64_CONTEXT;
#include "poppack.h"


#define EXCEPTION_MAXIMUM_PARAMETERS 15
#define EXCEPTION_NONCONTINUABLE  0x01
#define EXCEPTION_UNWINDING       0x02
#define EXCEPTION_EXIT_UNWIND     0x04
#define EXCEPTION_STACK_INVALID   0x08
#define EXCEPTION_NESTED_CALL     0x10
#define EXCEPTION_TARGET_UNWIND   0x20
#define EXCEPTION_COLLIDED_UNWIND 0x40
#define EXCEPTION_UNWIND (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND | \
                          EXCEPTION_TARGET_UNWIND | EXCEPTION_COLLIDED_UNWIND)

#define IS_UNWINDING(Flag) ((Flag & EXCEPTION_UNWIND) != 0)
#define IS_DISPATCHING(Flag) ((Flag & EXCEPTION_UNWIND) == 0)
#define IS_TARGET_UNWIND(Flag) (Flag & EXCEPTION_TARGET_UNWIND)

typedef struct _EXCEPTION_RECORD {
  DWORD ExceptionCode;
  DWORD ExceptionFlags;
  struct _EXCEPTION_RECORD *ExceptionRecord;
  PVOID ExceptionAddress;
  DWORD NumberParameters;
  ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD32 {
  DWORD ExceptionCode;
  DWORD ExceptionFlags;
  DWORD ExceptionRecord;
  DWORD ExceptionAddress;
  DWORD NumberParameters;
  DWORD ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD32,*PEXCEPTION_RECORD32;

typedef struct _EXCEPTION_RECORD64 {
  DWORD ExceptionCode;
  DWORD ExceptionFlags;
  DWORD64 ExceptionRecord;
  DWORD64 ExceptionAddress;
  DWORD NumberParameters;
  DWORD __unusedAlignment;
  DWORD64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD64,*PEXCEPTION_RECORD64;

typedef struct _EXCEPTION_POINTERS {
  PEXCEPTION_RECORD ExceptionRecord;
  PCONTEXT ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

typedef struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

#define SECURITY_MIN_SID_SIZE (sizeof(SID))

/******************************************************************************
 *                            Security Manager Types                          *
 ******************************************************************************/

/* Simple types */
typedef PVOID PSECURITY_DESCRIPTOR;
typedef DWORD SECURITY_INFORMATION, *PSECURITY_INFORMATION;
typedef DWORD ACCESS_MASK, *PACCESS_MASK;

typedef PVOID PACCESS_TOKEN;
typedef PVOID PSID;

#define DELETE                   0x00010000L
#define READ_CONTROL             0x00020000L
#define WRITE_DAC                0x00040000L
#define WRITE_OWNER              0x00080000L
#define SYNCHRONIZE              0x00100000L
#define STANDARD_RIGHTS_REQUIRED 0x000F0000L
#define STANDARD_RIGHTS_READ     READ_CONTROL
#define STANDARD_RIGHTS_WRITE    READ_CONTROL
#define STANDARD_RIGHTS_EXECUTE  READ_CONTROL
#define STANDARD_RIGHTS_ALL      0x001F0000L
#define SPECIFIC_RIGHTS_ALL      0x0000FFFFL
#define ACCESS_SYSTEM_SECURITY   0x01000000L
#define MAXIMUM_ALLOWED          0x02000000L
#define GENERIC_READ             0x80000000L
#define GENERIC_WRITE            0x40000000L
#define GENERIC_EXECUTE          0x20000000L
#define GENERIC_ALL              0x10000000L

typedef struct _GENERIC_MAPPING {
  ACCESS_MASK GenericRead;
  ACCESS_MASK GenericWrite;
  ACCESS_MASK GenericExecute;
  ACCESS_MASK GenericAll;
} GENERIC_MAPPING, *PGENERIC_MAPPING;

#define ACL_REVISION    2
#define ACL_REVISION_DS 4

#define ACL_REVISION1    1
#define ACL_REVISION2    2
#define ACL_REVISION3    3
#define ACL_REVISION4    4
#define MIN_ACL_REVISION ACL_REVISION2
#define MAX_ACL_REVISION ACL_REVISION4

typedef struct _ACL {
  BYTE AclRevision;
  BYTE Sbz1;
  WORD AclSize;
  WORD AceCount;
  WORD Sbz2;
} ACL, *PACL;

/* Current security descriptor revision value */
#define SECURITY_DESCRIPTOR_REVISION     (1)
#define SECURITY_DESCRIPTOR_REVISION1    (1)

/* Privilege attributes */
#define SE_PRIVILEGE_ENABLED_BY_DEFAULT (0x00000001L)
#define SE_PRIVILEGE_ENABLED            (0x00000002L)
#define SE_PRIVILEGE_REMOVED            (0x00000004L)
#define SE_PRIVILEGE_USED_FOR_ACCESS    (0x80000000L)

#define SE_PRIVILEGE_VALID_ATTRIBUTES   (SE_PRIVILEGE_ENABLED_BY_DEFAULT | \
                                         SE_PRIVILEGE_ENABLED            | \
                                         SE_PRIVILEGE_REMOVED            | \
                                         SE_PRIVILEGE_USED_FOR_ACCESS)

#include <pshpack4.h>
typedef struct _LUID_AND_ATTRIBUTES {
  LUID Luid;
  DWORD Attributes;
} LUID_AND_ATTRIBUTES, *PLUID_AND_ATTRIBUTES;
#include <poppack.h>

typedef LUID_AND_ATTRIBUTES LUID_AND_ATTRIBUTES_ARRAY[ANYSIZE_ARRAY];
typedef LUID_AND_ATTRIBUTES_ARRAY *PLUID_AND_ATTRIBUTES_ARRAY;

/* Privilege sets */
#define PRIVILEGE_SET_ALL_NECESSARY (1)

typedef struct _PRIVILEGE_SET {
  DWORD PrivilegeCount;
  DWORD Control;
  LUID_AND_ATTRIBUTES Privilege[ANYSIZE_ARRAY];
} PRIVILEGE_SET, *PPRIVILEGE_SET;

typedef enum _SECURITY_IMPERSONATION_LEVEL {
  SecurityAnonymous,
  SecurityIdentification,
  SecurityImpersonation,
  SecurityDelegation
} SECURITY_IMPERSONATION_LEVEL, * PSECURITY_IMPERSONATION_LEVEL;

#define SECURITY_MAX_IMPERSONATION_LEVEL SecurityDelegation
#define SECURITY_MIN_IMPERSONATION_LEVEL SecurityAnonymous
#define DEFAULT_IMPERSONATION_LEVEL      SecurityImpersonation
#define VALID_IMPERSONATION_LEVEL(Level) (((Level) >= SECURITY_MIN_IMPERSONATION_LEVEL) && ((Level) <= SECURITY_MAX_IMPERSONATION_LEVEL))

#define SECURITY_DYNAMIC_TRACKING (TRUE)
#define SECURITY_STATIC_TRACKING (FALSE)

typedef BOOLEAN SECURITY_CONTEXT_TRACKING_MODE, *PSECURITY_CONTEXT_TRACKING_MODE;

typedef struct _SECURITY_QUALITY_OF_SERVICE {
  DWORD Length;
  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
  SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode;
  BOOLEAN EffectiveOnly;
} SECURITY_QUALITY_OF_SERVICE, *PSECURITY_QUALITY_OF_SERVICE;

typedef struct _SE_IMPERSONATION_STATE {
  PACCESS_TOKEN Token;
  BOOLEAN CopyOnOpen;
  BOOLEAN EffectiveOnly;
  SECURITY_IMPERSONATION_LEVEL Level;
} SE_IMPERSONATION_STATE, *PSE_IMPERSONATION_STATE;


#define OWNER_SECURITY_INFORMATION (0x00000001L)
#define GROUP_SECURITY_INFORMATION (0x00000002L)
#define DACL_SECURITY_INFORMATION  (0x00000004L)
#define SACL_SECURITY_INFORMATION  (0x00000008L)
#define LABEL_SECURITY_INFORMATION (0x00000010L)

#define PROTECTED_DACL_SECURITY_INFORMATION   (0x80000000L)
#define PROTECTED_SACL_SECURITY_INFORMATION   (0x40000000L)
#define UNPROTECTED_DACL_SECURITY_INFORMATION (0x20000000L)
#define UNPROTECTED_SACL_SECURITY_INFORMATION (0x10000000L)

/* Auto inherit ACE flags */
#define SEF_DACL_AUTO_INHERIT               0x01
#define SEF_SACL_AUTO_INHERIT               0x02
#define SEF_DEFAULT_DESCRIPTOR_FOR_OBJECT   0x04
#define SEF_AVOID_PRIVILEGE_CHECK           0x08
#define SEF_AVOID_OWNER_CHECK               0x10
#define SEF_DEFAULT_OWNER_FROM_PARENT       0x20
#define SEF_DEFAULT_GROUP_FROM_PARENT       0x40
#define SEF_MACL_NO_WRITE_UP                0x100
#define SEF_MACL_NO_READ_UP                 0x200
#define SEF_MACL_NO_EXECUTE_UP              0x400
#define SEF_AI_USE_EXTRA_PARAMS             0x800
#define SEF_AVOID_OWNER_RESTRICTION         0x1000
#define SEF_MACL_VALID_FLAGS (SEF_MACL_NO_WRITE_UP | SEF_MACL_NO_READ_UP | SEF_MACL_NO_EXECUTE_UP)



/* Privilege token filtering flags */
#define DISABLE_MAX_PRIVILEGE 0x1
#define SANDBOX_INERT         0x2
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
#define LUA_TOKEN             0x4
#define WRITE_RESTRICTED      0x8
#endif



typedef enum _WELL_KNOWN_SID_TYPE {
  WinNullSid = 0,
  WinWorldSid = 1,
  WinLocalSid = 2,
  WinCreatorOwnerSid = 3,
  WinCreatorGroupSid = 4,
  WinCreatorOwnerServerSid = 5,
  WinCreatorGroupServerSid = 6,
  WinNtAuthoritySid = 7,
  WinDialupSid = 8,
  WinNetworkSid = 9,
  WinBatchSid = 10,
  WinInteractiveSid = 11,
  WinServiceSid = 12,
  WinAnonymousSid = 13,
  WinProxySid = 14,
  WinEnterpriseControllersSid = 15,
  WinSelfSid = 16,
  WinAuthenticatedUserSid = 17,
  WinRestrictedCodeSid = 18,
  WinTerminalServerSid = 19,
  WinRemoteLogonIdSid = 20,
  WinLogonIdsSid = 21,
  WinLocalSystemSid = 22,
  WinLocalServiceSid = 23,
  WinNetworkServiceSid = 24,
  WinBuiltinDomainSid = 25,
  WinBuiltinAdministratorsSid = 26,
  WinBuiltinUsersSid = 27,
  WinBuiltinGuestsSid = 28,
  WinBuiltinPowerUsersSid = 29,
  WinBuiltinAccountOperatorsSid = 30,
  WinBuiltinSystemOperatorsSid = 31,
  WinBuiltinPrintOperatorsSid = 32,
  WinBuiltinBackupOperatorsSid = 33,
  WinBuiltinReplicatorSid = 34,
  WinBuiltinPreWindows2000CompatibleAccessSid = 35,
  WinBuiltinRemoteDesktopUsersSid = 36,
  WinBuiltinNetworkConfigurationOperatorsSid = 37,
  WinAccountAdministratorSid = 38,
  WinAccountGuestSid = 39,
  WinAccountKrbtgtSid = 40,
  WinAccountDomainAdminsSid = 41,
  WinAccountDomainUsersSid = 42,
  WinAccountDomainGuestsSid = 43,
  WinAccountComputersSid = 44,
  WinAccountControllersSid = 45,
  WinAccountCertAdminsSid = 46,
  WinAccountSchemaAdminsSid = 47,
  WinAccountEnterpriseAdminsSid = 48,
  WinAccountPolicyAdminsSid = 49,
  WinAccountRasAndIasServersSid = 50,
  WinNTLMAuthenticationSid = 51,
  WinDigestAuthenticationSid = 52,
  WinSChannelAuthenticationSid = 53,
  WinThisOrganizationSid = 54,
  WinOtherOrganizationSid = 55,
  WinBuiltinIncomingForestTrustBuildersSid = 56,
  WinBuiltinPerfMonitoringUsersSid = 57,
  WinBuiltinPerfLoggingUsersSid = 58,
  WinBuiltinAuthorizationAccessSid = 59,
  WinBuiltinTerminalServerLicenseServersSid = 60,
  WinBuiltinDCOMUsersSid = 61,
  WinBuiltinIUsersSid = 62,
  WinIUserSid = 63,
  WinBuiltinCryptoOperatorsSid = 64,
  WinUntrustedLabelSid = 65,
  WinLowLabelSid = 66,
  WinMediumLabelSid = 67,
  WinHighLabelSid = 68,
  WinSystemLabelSid = 69,
  WinWriteRestrictedCodeSid = 70,
  WinCreatorOwnerRightsSid = 71,
  WinCacheablePrincipalsGroupSid = 72,
  WinNonCacheablePrincipalsGroupSid = 73,
  WinEnterpriseReadonlyControllersSid = 74,
  WinAccountReadonlyControllersSid = 75,
  WinBuiltinEventLogReadersGroup = 76,
  WinNewEnterpriseReadonlyControllersSid = 77,
  WinBuiltinCertSvcDComAccessGroup = 78,
  WinMediumPlusLabelSid = 79,
  WinLocalLogonSid = 80,
  WinConsoleLogonSid = 81,
  WinThisOrganizationCertificateSid = 82,
  WinApplicationPackageAuthoritySid = 83,
  WinBuiltinAnyPackageSid = 84,
  WinCapabilityInternetClientSid = 85,
  WinCapabilityInternetClientServerSid = 86,
  WinCapabilityPrivateNetworkClientServerSid = 87,
  WinCapabilityPicturesLibrarySid = 88,
  WinCapabilityVideosLibrarySid = 89,
  WinCapabilityMusicLibrarySid = 90,
  WinCapabilityDocumentsLibrarySid = 91,
  WinCapabilitySharedUserCertificatesSid = 92,
  WinCapabilityEnterpriseAuthenticationSid = 93,
  WinCapabilityRemovableStorageSid = 94,
  WinBuiltinRDSRemoteAccessServersSid = 95,
  WinBuiltinRDSEndpointServersSid = 96,
  WinBuiltinRDSManagementServersSid = 97,
  WinUserModeDriversSid = 98,
  WinBuiltinHyperVAdminsSid = 99,
  WinAccountCloneableControllersSid = 100,
  WinBuiltinAccessControlAssistanceOperatorsSid = 101,
  WinBuiltinRemoteManagementUsersSid = 102,
  WinAuthenticationAuthorityAssertedSid = 103,
  WinAuthenticationServiceAssertedSid = 104,
  WinLocalAccountSid = 105,
  WinLocalAccountAndAdministratorSid = 106,
  WinAccountProtectedUsersSid = 107,
} WELL_KNOWN_SID_TYPE;


#ifndef SID_IDENTIFIER_AUTHORITY_DEFINED
#define SID_IDENTIFIER_AUTHORITY_DEFINED
typedef struct _SID_IDENTIFIER_AUTHORITY {
  BYTE Value[6];
} SID_IDENTIFIER_AUTHORITY,*PSID_IDENTIFIER_AUTHORITY,*LPSID_IDENTIFIER_AUTHORITY;
#endif

#ifndef SID_DEFINED
#define SID_DEFINED
typedef struct _SID {
  BYTE Revision;
  BYTE SubAuthorityCount;
  SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
#ifdef MIDL_PASS
  [size_is(SubAuthorityCount)] DWORD SubAuthority[*];
#else
  DWORD SubAuthority[ANYSIZE_ARRAY];
#endif
} SID, *PISID;
#endif

#define SID_REVISION                    1
#define SID_MAX_SUB_AUTHORITIES         15
#define SID_RECOMMENDED_SUB_AUTHORITIES 1

#ifndef MIDL_PASS
#define SECURITY_MAX_SID_SIZE (sizeof(SID) - sizeof(DWORD) + (SID_MAX_SUB_AUTHORITIES * sizeof(DWORD)))
#endif

typedef enum _SID_NAME_USE {
  SidTypeUser = 1,
  SidTypeGroup,
  SidTypeDomain,
  SidTypeAlias,
  SidTypeWellKnownGroup,
  SidTypeDeletedAccount,
  SidTypeInvalid,
  SidTypeUnknown,
  SidTypeComputer,
  SidTypeLabel
} SID_NAME_USE, *PSID_NAME_USE;

typedef struct _SID_AND_ATTRIBUTES {
#ifdef MIDL_PASS
  PISID Sid;
#else
  PSID Sid;
#endif
  DWORD Attributes;
} SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;
typedef SID_AND_ATTRIBUTES SID_AND_ATTRIBUTES_ARRAY[ANYSIZE_ARRAY];
typedef SID_AND_ATTRIBUTES_ARRAY *PSID_AND_ATTRIBUTES_ARRAY;

#define SID_HASH_SIZE 32
typedef ULONG_PTR SID_HASH_ENTRY, *PSID_HASH_ENTRY;

typedef struct _SID_AND_ATTRIBUTES_HASH {
  DWORD SidCount;
  PSID_AND_ATTRIBUTES SidAttr;
  SID_HASH_ENTRY Hash[SID_HASH_SIZE];
} SID_AND_ATTRIBUTES_HASH, *PSID_AND_ATTRIBUTES_HASH;

/* Universal well-known SIDs */

#define SECURITY_NULL_SID_AUTHORITY         {0,0,0,0,0,0}

/* S-1-1 */
#define SECURITY_WORLD_SID_AUTHORITY        {0,0,0,0,0,1}

/* S-1-2 */
#define SECURITY_LOCAL_SID_AUTHORITY        {0,0,0,0,0,2}

/* S-1-3 */
#define SECURITY_CREATOR_SID_AUTHORITY      {0,0,0,0,0,3}

/* S-1-4 */
#define SECURITY_NON_UNIQUE_AUTHORITY       {0,0,0,0,0,4}

#define SECURITY_RESOURCE_MANAGER_AUTHORITY {0,0,0,0,0,9}

#define SECURITY_NULL_RID                   (0x00000000L)
#define SECURITY_WORLD_RID                  (0x00000000L)
#define SECURITY_LOCAL_RID                  (0x00000000L)
#define SECURITY_LOCAL_LOGON_RID            (0x00000001L)

#define SECURITY_CREATOR_OWNER_RID          (0x00000000L)
#define SECURITY_CREATOR_GROUP_RID          (0x00000001L)
#define SECURITY_CREATOR_OWNER_SERVER_RID   (0x00000002L)
#define SECURITY_CREATOR_GROUP_SERVER_RID   (0x00000003L)
#define SECURITY_CREATOR_OWNER_RIGHTS_RID   (0x00000004L)

/* NT well-known SIDs */

/* S-1-5 */
#define SECURITY_NT_AUTHORITY               {0,0,0,0,0,5}

#define SECURITY_DIALUP_RID                          (0x00000001L)
#define SECURITY_NETWORK_RID                         (0x00000002L)
#define SECURITY_BATCH_RID                           (0x00000003L)
#define SECURITY_INTERACTIVE_RID                     (0x00000004L)
#define SECURITY_LOGON_IDS_RID                       (0x00000005L)
#define SECURITY_LOGON_IDS_RID_COUNT                 (3L)
#define SECURITY_SERVICE_RID                         (0x00000006L)
#define SECURITY_ANONYMOUS_LOGON_RID                 (0x00000007L)
#define SECURITY_PROXY_RID                           (0x00000008L)
#define SECURITY_ENTERPRISE_CONTROLLERS_RID          (0x00000009L)
#define SECURITY_SERVER_LOGON_RID                    SECURITY_ENTERPRISE_CONTROLLERS_RID
#define SECURITY_PRINCIPAL_SELF_RID                  (0x0000000AL)
#define SECURITY_AUTHENTICATED_USER_RID              (0x0000000BL)
#define SECURITY_RESTRICTED_CODE_RID                 (0x0000000CL)
#define SECURITY_TERMINAL_SERVER_RID                 (0x0000000DL)
#define SECURITY_REMOTE_LOGON_RID                    (0x0000000EL)
#define SECURITY_THIS_ORGANIZATION_RID               (0x0000000FL)
#define SECURITY_IUSER_RID                           (0x00000011L)
#define SECURITY_LOCAL_SYSTEM_RID                    (0x00000012L)
#define SECURITY_LOCAL_SERVICE_RID                   (0x00000013L)
#define SECURITY_NETWORK_SERVICE_RID                 (0x00000014L)
#define SECURITY_NT_NON_UNIQUE                       (0x00000015L)
#define SECURITY_NT_NON_UNIQUE_SUB_AUTH_COUNT        (3L)
#define SECURITY_ENTERPRISE_READONLY_CONTROLLERS_RID (0x00000016L)

#define SECURITY_BUILTIN_DOMAIN_RID        (0x00000020L)
#define SECURITY_WRITE_RESTRICTED_CODE_RID (0x00000021L)


#define SECURITY_PACKAGE_BASE_RID     (0x00000040L)
#define SECURITY_PACKAGE_RID_COUNT    (2L)
#define SECURITY_PACKAGE_NTLM_RID     (0x0000000AL)
#define SECURITY_PACKAGE_SCHANNEL_RID (0x0000000EL)
#define SECURITY_PACKAGE_DIGEST_RID   (0x00000015L)

#define SECURITY_CRED_TYPE_BASE_RID          (0x00000041L)
#define SECURITY_CRED_TYPE_RID_COUNT         (2L)
#define SECURITY_CRED_TYPE_THIS_ORG_CERT_RID (0x00000001L)

#define SECURITY_MIN_BASE_RID                               (0x00000050L)
#define SECURITY_SERVICE_ID_BASE_RID                        (0x00000050L)
#define SECURITY_SERVICE_ID_RID_COUNT                       (6L)
#define SECURITY_RESERVED_ID_BASE_RID                       (0x00000051L)
#define SECURITY_APPPOOL_ID_BASE_RID                        (0x00000052L)
#define SECURITY_APPPOOL_ID_RID_COUNT                       (6L)
#define SECURITY_VIRTUALSERVER_ID_BASE_RID                  (0x00000053L)
#define SECURITY_VIRTUALSERVER_ID_RID_COUNT                 (6L)
#define SECURITY_USERMODEDRIVERHOST_ID_BASE_RID             (0x00000054L)
#define SECURITY_USERMODEDRIVERHOST_ID_RID_COUNT            (6L)
#define SECURITY_CLOUD_INFRASTRUCTURE_SERVICES_ID_BASE_RID  (0x00000055L)
#define SECURITY_CLOUD_INFRASTRUCTURE_SERVICES_ID_RID_COUNT (6L)
#define SECURITY_WMIHOST_ID_BASE_RID                        (0x00000056L)
#define SECURITY_WMIHOST_ID_RID_COUNT                       (6L)
#define SECURITY_TASK_ID_BASE_RID                           (0x00000057L)
#define SECURITY_NFS_ID_BASE_RID                            (0x00000058L)
#define SECURITY_COM_ID_BASE_RID                            (0x00000059L)
#define SECURITY_VIRTUALACCOUNT_ID_RID_COUNT                (6L)

#define SECURITY_MAX_BASE_RID (0x0000006FL)

#define SECURITY_MAX_ALWAYS_FILTERED (0x000003E7L)
#define SECURITY_MIN_NEVER_FILTERED  (0x000003E8L)

#define SECURITY_OTHER_ORGANIZATION_RID (0x000003E8L)

#define SECURITY_WINDOWSMOBILE_ID_BASE_RID (0x00000070L)

/* Well-known domain relative sub-authority values (RIDs) */

#define DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS (0x000001F2L)

#define FOREST_USER_RID_MAX (0x000001F3L)

/* Well-known users */

#define DOMAIN_USER_RID_ADMIN  (0x000001F4L)
#define DOMAIN_USER_RID_GUEST  (0x000001F5L)
#define DOMAIN_USER_RID_KRBTGT (0x000001F6L)

#define DOMAIN_USER_RID_MAX (0x000003E7L)

/* Well-known groups */

#define DOMAIN_GROUP_RID_ADMINS               (0x00000200L)
#define DOMAIN_GROUP_RID_USERS                (0x00000201L)
#define DOMAIN_GROUP_RID_GUESTS               (0x00000202L)
#define DOMAIN_GROUP_RID_COMPUTERS            (0x00000203L)
#define DOMAIN_GROUP_RID_CONTROLLERS          (0x00000204L)
#define DOMAIN_GROUP_RID_CERT_ADMINS          (0x00000205L)
#define DOMAIN_GROUP_RID_SCHEMA_ADMINS        (0x00000206L)
#define DOMAIN_GROUP_RID_ENTERPRISE_ADMINS    (0x00000207L)
#define DOMAIN_GROUP_RID_POLICY_ADMINS        (0x00000208L)
#define DOMAIN_GROUP_RID_READONLY_CONTROLLERS (0x00000209L)

/* Well-known aliases */

#define DOMAIN_ALIAS_RID_ADMINS      (0x00000220L)
#define DOMAIN_ALIAS_RID_USERS       (0x00000221L)
#define DOMAIN_ALIAS_RID_GUESTS      (0x00000222L)
#define DOMAIN_ALIAS_RID_POWER_USERS (0x00000223L)

#define DOMAIN_ALIAS_RID_ACCOUNT_OPS (0x00000224L)
#define DOMAIN_ALIAS_RID_SYSTEM_OPS  (0x00000225L)
#define DOMAIN_ALIAS_RID_PRINT_OPS   (0x00000226L)
#define DOMAIN_ALIAS_RID_BACKUP_OPS  (0x00000227L)

#define DOMAIN_ALIAS_RID_REPLICATOR                     (0x00000228L)
#define DOMAIN_ALIAS_RID_RAS_SERVERS                    (0x00000229L)
#define DOMAIN_ALIAS_RID_PREW2KCOMPACCESS               (0x0000022AL)
#define DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS           (0x0000022BL)
#define DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS      (0x0000022CL)
#define DOMAIN_ALIAS_RID_INCOMING_FOREST_TRUST_BUILDERS (0x0000022DL)

#define DOMAIN_ALIAS_RID_MONITORING_USERS    (0x0000022EL)
#define DOMAIN_ALIAS_RID_LOGGING_USERS       (0x0000022FL)
#define DOMAIN_ALIAS_RID_AUTHORIZATIONACCESS (0x00000230L)
#define DOMAIN_ALIAS_RID_TS_LICENSE_SERVERS  (0x00000231L)
#define DOMAIN_ALIAS_RID_DCOM_USERS          (0x00000232L)

#define DOMAIN_ALIAS_RID_IUSERS                         (0x00000238L)
#define DOMAIN_ALIAS_RID_CRYPTO_OPERATORS               (0x00000239L)
#define DOMAIN_ALIAS_RID_CACHEABLE_PRINCIPALS_GROUP     (0x0000023BL)
#define DOMAIN_ALIAS_RID_NON_CACHEABLE_PRINCIPALS_GROUP (0x0000023CL)
#define DOMAIN_ALIAS_RID_EVENT_LOG_READERS_GROUP        (0x0000023DL)
#define DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP      (0x0000023EL)

#define SECURITY_MANDATORY_LABEL_AUTHORITY       {0,0,0,0,0,16}
#define SECURITY_MANDATORY_UNTRUSTED_RID         (0x00000000L)
#define SECURITY_MANDATORY_LOW_RID               (0x00001000L)
#define SECURITY_MANDATORY_MEDIUM_RID            (0x00002000L)
#define SECURITY_MANDATORY_HIGH_RID              (0x00003000L)
#define SECURITY_MANDATORY_SYSTEM_RID            (0x00004000L)
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID (0x00005000L)

/* SECURITY_MANDATORY_MAXIMUM_USER_RID is the highest RID that
   can be set by a usermode caller.*/

#define SECURITY_MANDATORY_MAXIMUM_USER_RID SECURITY_MANDATORY_SYSTEM_RID

#define MANDATORY_LEVEL_TO_MANDATORY_RID(IL) (IL * 0x1000)

/* Allocate the System Luid.  The first 1000 LUIDs are reserved.
   Use #999 here (0x3e7 = 999) */

#define SYSTEM_LUID          {0x3e7, 0x0}
#define ANONYMOUS_LOGON_LUID {0x3e6, 0x0}
#define LOCALSERVICE_LUID    {0x3e5, 0x0}
#define NETWORKSERVICE_LUID  {0x3e4, 0x0}
#define IUSER_LUID           {0x3e3, 0x0}

/* Logon session reference flags */

#define SEP_LOGON_SESSION_TERMINATION_NOTIFY   0x0001

typedef struct _ACE_HEADER {
  BYTE AceType;
  BYTE AceFlags;
  WORD AceSize;
} ACE_HEADER, *PACE_HEADER;

#define ACCESS_MIN_MS_ACE_TYPE                  (0x0)
#define ACCESS_ALLOWED_ACE_TYPE                 (0x0)
#define ACCESS_DENIED_ACE_TYPE                  (0x1)
#define SYSTEM_AUDIT_ACE_TYPE                   (0x2)
#define SYSTEM_ALARM_ACE_TYPE                   (0x3)
#define ACCESS_MAX_MS_V2_ACE_TYPE               (0x3)
#define ACCESS_ALLOWED_COMPOUND_ACE_TYPE        (0x4)
#define ACCESS_MAX_MS_V3_ACE_TYPE               (0x4)
#define ACCESS_MIN_MS_OBJECT_ACE_TYPE           (0x5)
#define ACCESS_ALLOWED_OBJECT_ACE_TYPE          (0x5)
#define ACCESS_DENIED_OBJECT_ACE_TYPE           (0x6)
#define SYSTEM_AUDIT_OBJECT_ACE_TYPE            (0x7)
#define SYSTEM_ALARM_OBJECT_ACE_TYPE            (0x8)
#define ACCESS_MAX_MS_OBJECT_ACE_TYPE           (0x8)
#define ACCESS_MAX_MS_V4_ACE_TYPE               (0x8)
#define ACCESS_MAX_MS_ACE_TYPE                  (0x8)
#define ACCESS_ALLOWED_CALLBACK_ACE_TYPE        (0x9)
#define ACCESS_DENIED_CALLBACK_ACE_TYPE         (0xA)
#define ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE (0xB)
#define ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  (0xC)
#define SYSTEM_AUDIT_CALLBACK_ACE_TYPE          (0xD)
#define SYSTEM_ALARM_CALLBACK_ACE_TYPE          (0xE)
#define SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   (0xF)
#define SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   (0x10)
#define ACCESS_MAX_MS_V5_ACE_TYPE               (0x11)
#define SYSTEM_MANDATORY_LABEL_ACE_TYPE         (0x11)

/* The following are the inherit flags that go into the AceFlags field
   of an Ace header. */

#define OBJECT_INHERIT_ACE       (0x1)
#define CONTAINER_INHERIT_ACE    (0x2)
#define NO_PROPAGATE_INHERIT_ACE (0x4)
#define INHERIT_ONLY_ACE         (0x8)
#define INHERITED_ACE            (0x10)
#define VALID_INHERIT_FLAGS      (0x1F)

#define SUCCESSFUL_ACCESS_ACE_FLAG (0x40)
#define FAILED_ACCESS_ACE_FLAG     (0x80)

typedef struct _ACCESS_ALLOWED_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD SidStart;
} ACCESS_ALLOWED_ACE, *PACCESS_ALLOWED_ACE;

typedef struct _ACCESS_DENIED_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD SidStart;
} ACCESS_DENIED_ACE, *PACCESS_DENIED_ACE;

typedef struct _ACCESS_ALLOWED_OBJECT_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD Flags;
  GUID ObjectType;
  GUID InheritedObjectType;
  DWORD SidStart;
} ACCESS_ALLOWED_OBJECT_ACE, *PACCESS_ALLOWED_OBJECT_ACE;

typedef struct _ACCESS_DENIED_OBJECT_ACE {
  ACE_HEADER  Header;
  ACCESS_MASK Mask;
  DWORD Flags;
  GUID ObjectType;
  GUID InheritedObjectType;
  DWORD SidStart;
} ACCESS_DENIED_OBJECT_ACE, *PACCESS_DENIED_OBJECT_ACE;

typedef struct _SYSTEM_AUDIT_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD SidStart;
} SYSTEM_AUDIT_ACE, *PSYSTEM_AUDIT_ACE;

typedef struct _SYSTEM_ALARM_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD SidStart;
} SYSTEM_ALARM_ACE, *PSYSTEM_ALARM_ACE;

typedef struct _SYSTEM_MANDATORY_LABEL_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD SidStart;
} SYSTEM_MANDATORY_LABEL_ACE, *PSYSTEM_MANDATORY_LABEL_ACE;

#define SYSTEM_MANDATORY_LABEL_NO_WRITE_UP   0x1
#define SYSTEM_MANDATORY_LABEL_NO_READ_UP    0x2
#define SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP 0x4
#define SYSTEM_MANDATORY_LABEL_VALID_MASK    (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | \
                                              SYSTEM_MANDATORY_LABEL_NO_READ_UP  | \
                                              SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP)

#define SECURITY_DESCRIPTOR_MIN_LENGTH (sizeof(SECURITY_DESCRIPTOR))

typedef WORD SECURITY_DESCRIPTOR_CONTROL, *PSECURITY_DESCRIPTOR_CONTROL;

#define SE_OWNER_DEFAULTED       0x0001
#define SE_GROUP_DEFAULTED       0x0002
#define SE_DACL_PRESENT          0x0004
#define SE_DACL_DEFAULTED        0x0008
#define SE_SACL_PRESENT          0x0010
#define SE_SACL_DEFAULTED        0x0020
#define SE_DACL_UNTRUSTED        0x0040
#define SE_SERVER_SECURITY       0x0080
#define SE_DACL_AUTO_INHERIT_REQ 0x0100
#define SE_SACL_AUTO_INHERIT_REQ 0x0200
#define SE_DACL_AUTO_INHERITED   0x0400
#define SE_SACL_AUTO_INHERITED   0x0800
#define SE_DACL_PROTECTED        0x1000
#define SE_SACL_PROTECTED        0x2000
#define SE_RM_CONTROL_VALID      0x4000
#define SE_SELF_RELATIVE         0x8000

typedef struct _SECURITY_DESCRIPTOR_RELATIVE {
  BYTE Revision;
  BYTE Sbz1;
  SECURITY_DESCRIPTOR_CONTROL Control;
  DWORD Owner;
  DWORD Group;
  DWORD Sacl;
  DWORD Dacl;
} SECURITY_DESCRIPTOR_RELATIVE, *PISECURITY_DESCRIPTOR_RELATIVE;

typedef struct _SECURITY_DESCRIPTOR {
  BYTE Revision;
  BYTE Sbz1;
  SECURITY_DESCRIPTOR_CONTROL Control;
  PSID Owner;
  PSID Group;
  PACL Sacl;
  PACL Dacl;
} SECURITY_DESCRIPTOR, *PISECURITY_DESCRIPTOR;

typedef struct _OBJECT_TYPE_LIST {
  WORD Level;
  WORD Sbz;
  GUID *ObjectType;
} OBJECT_TYPE_LIST, *POBJECT_TYPE_LIST;

#define ACCESS_OBJECT_GUID       0
#define ACCESS_PROPERTY_SET_GUID 1
#define ACCESS_PROPERTY_GUID     2
#define ACCESS_MAX_LEVEL         4

typedef enum _AUDIT_EVENT_TYPE {
  AuditEventObjectAccess,
  AuditEventDirectoryServiceAccess
} AUDIT_EVENT_TYPE, *PAUDIT_EVENT_TYPE;

#define AUDIT_ALLOW_NO_PRIVILEGE 0x1

#define ACCESS_DS_SOURCE_A "DS"
#define ACCESS_DS_SOURCE_W L"DS"
#define ACCESS_DS_OBJECT_TYPE_NAME_A "Directory Service Object"
#define ACCESS_DS_OBJECT_TYPE_NAME_W L"Directory Service Object"

#define ACCESS_REASON_TYPE_MASK 0xffff0000
#define ACCESS_REASON_DATA_MASK 0x0000ffff

typedef enum _ACCESS_REASON_TYPE {
  AccessReasonNone = 0x00000000,
  AccessReasonAllowedAce = 0x00010000,
  AccessReasonDeniedAce = 0x00020000,
  AccessReasonAllowedParentAce = 0x00030000,
  AccessReasonDeniedParentAce = 0x00040000,
  AccessReasonMissingPrivilege = 0x00100000,
  AccessReasonFromPrivilege = 0x00200000,
  AccessReasonIntegrityLevel = 0x00300000,
  AccessReasonOwnership = 0x00400000,
  AccessReasonNullDacl = 0x00500000,
  AccessReasonEmptyDacl = 0x00600000,
  AccessReasonNoSD = 0x00700000,
  AccessReasonNoGrant = 0x00800000
} ACCESS_REASON_TYPE;

typedef DWORD ACCESS_REASON;

typedef struct _ACCESS_REASONS {
  ACCESS_REASON Data[32];
} ACCESS_REASONS, *PACCESS_REASONS;

#define SE_SECURITY_DESCRIPTOR_FLAG_NO_OWNER_ACE 0x00000001
#define SE_SECURITY_DESCRIPTOR_FLAG_NO_LABEL_ACE 0x00000002
#define SE_SECURITY_DESCRIPTOR_VALID_FLAGS       0x00000003

typedef struct _SE_SECURITY_DESCRIPTOR {
  DWORD Size;
  DWORD Flags;
  PSECURITY_DESCRIPTOR SecurityDescriptor;
} SE_SECURITY_DESCRIPTOR, *PSE_SECURITY_DESCRIPTOR;

typedef struct _SE_ACCESS_REQUEST {
  DWORD Size;
  PSE_SECURITY_DESCRIPTOR SeSecurityDescriptor;
  ACCESS_MASK DesiredAccess;
  ACCESS_MASK PreviouslyGrantedAccess;
  PSID PrincipalSelfSid;
  PGENERIC_MAPPING GenericMapping;
  DWORD ObjectTypeListCount;
  POBJECT_TYPE_LIST ObjectTypeList;
} SE_ACCESS_REQUEST, *PSE_ACCESS_REQUEST;

#define TOKEN_ASSIGN_PRIMARY    (0x0001)
#define TOKEN_DUPLICATE         (0x0002)
#define TOKEN_IMPERSONATE       (0x0004)
#define TOKEN_QUERY             (0x0008)
#define TOKEN_QUERY_SOURCE      (0x0010)
#define TOKEN_ADJUST_PRIVILEGES (0x0020)
#define TOKEN_ADJUST_GROUPS     (0x0040)
#define TOKEN_ADJUST_DEFAULT    (0x0080)
#define TOKEN_ADJUST_SESSIONID  (0x0100)

#define TOKEN_ALL_ACCESS_P (STANDARD_RIGHTS_REQUIRED |\
                            TOKEN_ASSIGN_PRIMARY     |\
                            TOKEN_DUPLICATE          |\
                            TOKEN_IMPERSONATE        |\
                            TOKEN_QUERY              |\
                            TOKEN_QUERY_SOURCE       |\
                            TOKEN_ADJUST_PRIVILEGES  |\
                            TOKEN_ADJUST_GROUPS      |\
                            TOKEN_ADJUST_DEFAULT)

#if ((defined(_WIN32_WINNT) && (_WIN32_WINNT > 0x0400)) || (!defined(_WIN32_WINNT)))
#define TOKEN_ALL_ACCESS (TOKEN_ALL_ACCESS_P | TOKEN_ADJUST_SESSIONID)
#else
#define TOKEN_ALL_ACCESS (TOKEN_ALL_ACCESS_P)
#endif

#define TOKEN_READ (STANDARD_RIGHTS_READ | TOKEN_QUERY)

#define TOKEN_WRITE (STANDARD_RIGHTS_WRITE   |\
                     TOKEN_ADJUST_PRIVILEGES |\
                     TOKEN_ADJUST_GROUPS     |\
                     TOKEN_ADJUST_DEFAULT)

#define TOKEN_EXECUTE (STANDARD_RIGHTS_EXECUTE)

typedef enum _TOKEN_TYPE {
  TokenPrimary = 1,
  TokenImpersonation
} TOKEN_TYPE, *PTOKEN_TYPE;

typedef enum _TOKEN_INFORMATION_CLASS {
  TokenUser = 1,
  TokenGroups,
  TokenPrivileges,
  TokenOwner,
  TokenPrimaryGroup,
  TokenDefaultDacl,
  TokenSource,
  TokenType,
  TokenImpersonationLevel,
  TokenStatistics,
  TokenRestrictedSids,
  TokenSessionId,
  TokenGroupsAndPrivileges,
  TokenSessionReference,
  TokenSandBoxInert,
  TokenAuditPolicy,
  TokenOrigin,
  TokenElevationType,
  TokenLinkedToken,
  TokenElevation,
  TokenHasRestrictions,
  TokenAccessInformation,
  TokenVirtualizationAllowed,
  TokenVirtualizationEnabled,
  TokenIntegrityLevel,
  TokenUIAccess,
  TokenMandatoryPolicy,
  TokenLogonSid,
  TokenIsAppContainer,
  TokenCapabilities,
  TokenAppContainerSid,
  TokenAppContainerNumber,
  TokenUserClaimAttributes,
  TokenDeviceClaimAttributes,
  TokenRestrictedUserClaimAttributes,
  TokenRestrictedDeviceClaimAttributes,
  TokenDeviceGroups,
  TokenRestrictedDeviceGroups,
  TokenSecurityAttributes,
  TokenIsRestricted,
  MaxTokenInfoClass
} TOKEN_INFORMATION_CLASS, *PTOKEN_INFORMATION_CLASS;

typedef struct _TOKEN_USER {
  SID_AND_ATTRIBUTES User;
} TOKEN_USER, *PTOKEN_USER;

typedef struct _TOKEN_GROUPS {
  DWORD GroupCount;
#ifdef MIDL_PASS
  [size_is(GroupCount)] SID_AND_ATTRIBUTES Groups[*];
#else
  SID_AND_ATTRIBUTES Groups[ANYSIZE_ARRAY];
#endif
} TOKEN_GROUPS, *PTOKEN_GROUPS, *LPTOKEN_GROUPS;

typedef struct _TOKEN_PRIVILEGES {
  DWORD PrivilegeCount;
  LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
} TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES, *LPTOKEN_PRIVILEGES;

typedef struct _TOKEN_OWNER {
  PSID Owner;
} TOKEN_OWNER, *PTOKEN_OWNER;

typedef struct _TOKEN_PRIMARY_GROUP {
  PSID PrimaryGroup;
} TOKEN_PRIMARY_GROUP, *PTOKEN_PRIMARY_GROUP;

typedef struct _TOKEN_DEFAULT_DACL {
  PACL DefaultDacl;
} TOKEN_DEFAULT_DACL, *PTOKEN_DEFAULT_DACL;

typedef struct _TOKEN_GROUPS_AND_PRIVILEGES {
  DWORD SidCount;
  DWORD SidLength;
  PSID_AND_ATTRIBUTES Sids;
  DWORD RestrictedSidCount;
  DWORD RestrictedSidLength;
  PSID_AND_ATTRIBUTES RestrictedSids;
  DWORD PrivilegeCount;
  DWORD PrivilegeLength;
  PLUID_AND_ATTRIBUTES Privileges;
  LUID AuthenticationId;
} TOKEN_GROUPS_AND_PRIVILEGES, *PTOKEN_GROUPS_AND_PRIVILEGES;

typedef struct _TOKEN_LINKED_TOKEN {
  HANDLE LinkedToken;
} TOKEN_LINKED_TOKEN, *PTOKEN_LINKED_TOKEN;

typedef struct _TOKEN_ELEVATION {
  DWORD TokenIsElevated;
} TOKEN_ELEVATION, *PTOKEN_ELEVATION;

typedef struct _TOKEN_MANDATORY_LABEL {
  SID_AND_ATTRIBUTES Label;
} TOKEN_MANDATORY_LABEL, *PTOKEN_MANDATORY_LABEL;

#define TOKEN_MANDATORY_POLICY_OFF             0x0
#define TOKEN_MANDATORY_POLICY_NO_WRITE_UP     0x1
#define TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN 0x2

#define TOKEN_MANDATORY_POLICY_VALID_MASK (TOKEN_MANDATORY_POLICY_NO_WRITE_UP | \
                                           TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN)

#define POLICY_AUDIT_SUBCATEGORY_COUNT (56)

typedef struct _TOKEN_AUDIT_POLICY {
  BYTE PerUserPolicy[((POLICY_AUDIT_SUBCATEGORY_COUNT) >> 1) + 1];
} TOKEN_AUDIT_POLICY, *PTOKEN_AUDIT_POLICY;

#define TOKEN_SOURCE_LENGTH 8

typedef struct _TOKEN_SOURCE {
  CHAR SourceName[TOKEN_SOURCE_LENGTH];
  LUID SourceIdentifier;
} TOKEN_SOURCE, *PTOKEN_SOURCE;

#include <pshpack4.h>
typedef struct _TOKEN_STATISTICS {
  LUID TokenId;
  LUID AuthenticationId;
  LARGE_INTEGER ExpirationTime;
  TOKEN_TYPE TokenType;
  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
  DWORD DynamicCharged;
  DWORD DynamicAvailable;
  DWORD GroupCount;
  DWORD PrivilegeCount;
  LUID ModifiedId;
} TOKEN_STATISTICS, *PTOKEN_STATISTICS;
#include <poppack.h>

typedef struct _TOKEN_CONTROL {
  LUID TokenId;
  LUID AuthenticationId;
  LUID ModifiedId;
  TOKEN_SOURCE TokenSource;
} TOKEN_CONTROL, *PTOKEN_CONTROL;

typedef struct _TOKEN_ORIGIN {
  LUID OriginatingLogonSession;
} TOKEN_ORIGIN, *PTOKEN_ORIGIN;

typedef enum _MANDATORY_LEVEL {
  MandatoryLevelUntrusted = 0,
  MandatoryLevelLow,
  MandatoryLevelMedium,
  MandatoryLevelHigh,
  MandatoryLevelSystem,
  MandatoryLevelSecureProcess,
  MandatoryLevelCount
} MANDATORY_LEVEL, *PMANDATORY_LEVEL;


typedef struct _SYSTEM_AUDIT_OBJECT_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD Flags;
  GUID ObjectType;
  GUID InheritedObjectType;
  DWORD SidStart;
} SYSTEM_AUDIT_OBJECT_ACE,*PSYSTEM_AUDIT_OBJECT_ACE;

typedef struct _SYSTEM_ALARM_OBJECT_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD Flags;
  GUID ObjectType;
  GUID InheritedObjectType;
  DWORD SidStart;
} SYSTEM_ALARM_OBJECT_ACE,*PSYSTEM_ALARM_OBJECT_ACE;

typedef struct _ACCESS_ALLOWED_CALLBACK_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD SidStart;
} ACCESS_ALLOWED_CALLBACK_ACE, *PACCESS_ALLOWED_CALLBACK_ACE;

typedef struct _ACCESS_DENIED_CALLBACK_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD SidStart;
} ACCESS_DENIED_CALLBACK_ACE, *PACCESS_DENIED_CALLBACK_ACE;

typedef struct _SYSTEM_AUDIT_CALLBACK_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD SidStart;
} SYSTEM_AUDIT_CALLBACK_ACE, *PSYSTEM_AUDIT_CALLBACK_ACE;

typedef struct _SYSTEM_ALARM_CALLBACK_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD SidStart;
} SYSTEM_ALARM_CALLBACK_ACE, *PSYSTEM_ALARM_CALLBACK_ACE;

typedef struct _ACCESS_ALLOWED_CALLBACK_OBJECT_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD Flags;
  GUID ObjectType;
  GUID InheritedObjectType;
  DWORD SidStart;
} ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, *PACCESS_ALLOWED_CALLBACK_OBJECT_ACE;

typedef struct _ACCESS_DENIED_CALLBACK_OBJECT_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD Flags;
  GUID ObjectType;
  GUID InheritedObjectType;
  DWORD SidStart;
} ACCESS_DENIED_CALLBACK_OBJECT_ACE, *PACCESS_DENIED_CALLBACK_OBJECT_ACE;

typedef struct _SYSTEM_AUDIT_CALLBACK_OBJECT_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD Flags;
  GUID ObjectType;
  GUID InheritedObjectType;
  DWORD SidStart;
} SYSTEM_AUDIT_CALLBACK_OBJECT_ACE, *PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE;

typedef struct _SYSTEM_ALARM_CALLBACK_OBJECT_ACE {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD Flags;
  GUID ObjectType;
  GUID InheritedObjectType;
  DWORD SidStart;
} SYSTEM_ALARM_CALLBACK_OBJECT_ACE, *PSYSTEM_ALARM_CALLBACK_OBJECT_ACE;

typedef enum _TOKEN_ELEVATION_TYPE {
    TokenElevationTypeDefault = 1,
    TokenElevationTypeFull,
    TokenElevationTypeLimited,
} TOKEN_ELEVATION_TYPE, *PTOKEN_ELEVATION_TYPE;

typedef struct _QUOTA_LIMITS {
  SIZE_T PagedPoolLimit;
  SIZE_T NonPagedPoolLimit;
  SIZE_T MinimumWorkingSetSize;
  SIZE_T MaximumWorkingSetSize;
  SIZE_T PagefileLimit;
  LARGE_INTEGER TimeLimit;
} QUOTA_LIMITS,*PQUOTA_LIMITS;

typedef union _RATE_QUOTA_LIMIT {
  DWORD RateData;
  struct {
    DWORD RatePercent : 7;
    DWORD Reserved0 : 25;
  } DUMMYSTRUCTNAME;
} RATE_QUOTA_LIMIT, *PRATE_QUOTA_LIMIT;

typedef struct _QUOTA_LIMITS_EX {
  SIZE_T PagedPoolLimit;
  SIZE_T NonPagedPoolLimit;
  SIZE_T MinimumWorkingSetSize;
  SIZE_T MaximumWorkingSetSize;
  SIZE_T PagefileLimit;
  LARGE_INTEGER TimeLimit;
  SIZE_T Reserved1;
  SIZE_T Reserved2;
  SIZE_T Reserved3;
  SIZE_T Reserved4;
  DWORD Flags;
  RATE_QUOTA_LIMIT CpuRateLimit;
} QUOTA_LIMITS_EX, *PQUOTA_LIMITS_EX;

typedef struct _IO_COUNTERS {
  ULONGLONG ReadOperationCount;
  ULONGLONG WriteOperationCount;
  ULONGLONG OtherOperationCount;
  ULONGLONG ReadTransferCount;
  ULONGLONG WriteTransferCount;
  ULONGLONG OtherTransferCount;
} IO_COUNTERS, *PIO_COUNTERS;

typedef struct _FILE_NOTIFY_INFORMATION {
  DWORD NextEntryOffset;
  DWORD Action;
  DWORD FileNameLength;
  WCHAR FileName[1];
} FILE_NOTIFY_INFORMATION,*PFILE_NOTIFY_INFORMATION;

typedef struct _TAPE_ERASE {
  DWORD Type;
  BOOLEAN Immediate;
} TAPE_ERASE, *PTAPE_ERASE;

typedef struct _TAPE_GET_DRIVE_PARAMETERS {
  BOOLEAN ECC;
  BOOLEAN Compression;
  BOOLEAN DataPadding;
  BOOLEAN ReportSetmarks;
  DWORD DefaultBlockSize;
  DWORD MaximumBlockSize;
  DWORD MinimumBlockSize;
  DWORD MaximumPartitionCount;
  DWORD FeaturesLow;
  DWORD FeaturesHigh;
  DWORD EOTWarningZoneSize;
} TAPE_GET_DRIVE_PARAMETERS, *PTAPE_GET_DRIVE_PARAMETERS;

typedef struct _TAPE_GET_MEDIA_PARAMETERS {
  LARGE_INTEGER Capacity;
  LARGE_INTEGER Remaining;
  DWORD BlockSize;
  DWORD PartitionCount;
  BOOLEAN WriteProtected;
} TAPE_GET_MEDIA_PARAMETERS, *PTAPE_GET_MEDIA_PARAMETERS;

typedef struct _TAPE_GET_POSITION {
  DWORD Type;
  DWORD Partition;
  LARGE_INTEGER Offset;
} TAPE_GET_POSITION, *PTAPE_GET_POSITION;

typedef struct _TAPE_PREPARE {
  DWORD Operation;
  BOOLEAN Immediate;
} TAPE_PREPARE, *PTAPE_PREPARE;

typedef struct _TAPE_SET_DRIVE_PARAMETERS {
  BOOLEAN ECC;
  BOOLEAN Compression;
  BOOLEAN DataPadding;
  BOOLEAN ReportSetmarks;
  DWORD EOTWarningZoneSize;
} TAPE_SET_DRIVE_PARAMETERS, *PTAPE_SET_DRIVE_PARAMETERS;

typedef struct _TAPE_SET_MEDIA_PARAMETERS {
  DWORD BlockSize;
} TAPE_SET_MEDIA_PARAMETERS,*PTAPE_SET_MEDIA_PARAMETERS;

typedef struct _TAPE_SET_POSITION {
  DWORD Method;
  DWORD Partition;
  LARGE_INTEGER Offset;
  BOOLEAN Immediate;
} TAPE_SET_POSITION, *PTAPE_SET_POSITION;

typedef struct _TAPE_WRITE_MARKS {
  DWORD Type;
  DWORD Count;
  BOOLEAN Immediate;
} TAPE_WRITE_MARKS, *PTAPE_WRITE_MARKS;

typedef struct _TAPE_CREATE_PARTITION {
  DWORD Method;
  DWORD Count;
  DWORD Size;
} TAPE_CREATE_PARTITION, *PTAPE_CREATE_PARTITION;

typedef struct _MEMORY_BASIC_INFORMATION {
  PVOID BaseAddress;
  PVOID AllocationBase;
  DWORD AllocationProtect;
  SIZE_T RegionSize;
  DWORD State;
  DWORD Protect;
  DWORD Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

typedef struct _MESSAGE_RESOURCE_ENTRY {
  WORD Length;
  WORD Flags;
  BYTE Text[1];
} MESSAGE_RESOURCE_ENTRY, *PMESSAGE_RESOURCE_ENTRY;

typedef struct _MESSAGE_RESOURCE_BLOCK {
  DWORD LowId;
  DWORD HighId;
  DWORD OffsetToEntries;
} MESSAGE_RESOURCE_BLOCK, *PMESSAGE_RESOURCE_BLOCK;

typedef struct _MESSAGE_RESOURCE_DATA {
  DWORD NumberOfBlocks;
  MESSAGE_RESOURCE_BLOCK Blocks[1];
} MESSAGE_RESOURCE_DATA,*PMESSAGE_RESOURCE_DATA;

//
// Slist Header
//
#ifndef _SLIST_HEADER_
#define _SLIST_HEADER_

#if defined(_WIN64)

typedef struct DECLSPEC_ALIGN(16) _SLIST_ENTRY {
  struct _SLIST_ENTRY *Next;
} SLIST_ENTRY, *PSLIST_ENTRY;

typedef struct _SLIST_ENTRY32 {
  DWORD Next;
} SLIST_ENTRY32, *PSLIST_ENTRY32;

typedef union DECLSPEC_ALIGN(16) _SLIST_HEADER {
  _ANONYMOUS_STRUCT struct {
    ULONGLONG Alignment;
    ULONGLONG Region;
  } DUMMYSTRUCTNAME;
  struct {
    ULONGLONG Depth:16;
    ULONGLONG Sequence:9;
    ULONGLONG NextEntry:39;
    ULONGLONG HeaderType:1;
    ULONGLONG Init:1;
    ULONGLONG Reserved:59;
    ULONGLONG Region:3;
  } Header8;
  struct {
    ULONGLONG Depth:16;
    ULONGLONG Sequence:48;
    ULONGLONG HeaderType:1;
    ULONGLONG Init:1;
    ULONGLONG Reserved:2;
    ULONGLONG NextEntry:60;
  } Header16;
  struct {
    ULONGLONG Depth:16;
    ULONGLONG Sequence:48;
    ULONGLONG HeaderType:1;
    ULONGLONG Reserved:3;
    ULONGLONG NextEntry:60;
  } HeaderX64;
} SLIST_HEADER, *PSLIST_HEADER;

typedef union _SLIST_HEADER32{
  ULONGLONG Alignment;
  _ANONYMOUS_STRUCT struct {
    SLIST_ENTRY32 Next;
    WORD Depth;
    WORD Sequence;
  } DUMMYSTRUCTNAME;
} SLIST_HEADER32, *PSLIST_HEADER32;

#else

#define SLIST_ENTRY SINGLE_LIST_ENTRY
#define _SLIST_ENTRY _SINGLE_LIST_ENTRY
#define PSLIST_ENTRY PSINGLE_LIST_ENTRY

typedef SLIST_ENTRY SLIST_ENTRY32, *PSLIST_ENTRY32;

typedef union _SLIST_HEADER {
  ULONGLONG Alignment;
  _ANONYMOUS_STRUCT struct {
    SLIST_ENTRY Next;
    WORD Depth;
    WORD Sequence;
  } DUMMYSTRUCTNAME;
} SLIST_HEADER, *PSLIST_HEADER;

typedef SLIST_HEADER SLIST_HEADER32, *PSLIST_HEADER32;

#endif /* defined(_WIN64) */

#endif /* _SLIST_HEADER_ */

NTSYSAPI
VOID
NTAPI
RtlInitializeSListHead(
  _Out_ PSLIST_HEADER ListHead);

_Must_inspect_result_
NTSYSAPI
PSLIST_ENTRY
NTAPI
RtlFirstEntrySList(
  _In_ const SLIST_HEADER *ListHead);

NTSYSAPI
PSLIST_ENTRY
NTAPI
RtlInterlockedPopEntrySList(
  _Inout_ PSLIST_HEADER ListHead);

NTSYSAPI
PSLIST_ENTRY
NTAPI
RtlInterlockedPushEntrySList(
  _Inout_ PSLIST_HEADER ListHead,
  _Inout_ __drv_aliasesMem PSLIST_ENTRY ListEntry);

NTSYSAPI
PSLIST_ENTRY
NTAPI
RtlInterlockedFlushSList(
  _Inout_ PSLIST_HEADER ListHead);

NTSYSAPI
WORD
NTAPI
RtlQueryDepthSList(
  _In_ PSLIST_HEADER ListHead);

#ifndef _RTL_RUN_ONCE_DEF
#define _RTL_RUN_ONCE_DEF

#define RTL_RUN_ONCE_CHECK_ONLY 0x00000001UL
#define RTL_RUN_ONCE_ASYNC 0x00000002UL
#define RTL_RUN_ONCE_INIT_FAILED 0x00000004UL

#define RTL_RUN_ONCE_INIT {0}

typedef union _RTL_RUN_ONCE {
  PVOID Ptr;
} RTL_RUN_ONCE, *PRTL_RUN_ONCE;

typedef DWORD WINAPI RTL_RUN_ONCE_INIT_FN(PRTL_RUN_ONCE, PVOID, PVOID*);
typedef RTL_RUN_ONCE_INIT_FN *PRTL_RUN_ONCE_INIT_FN;

NTSYSAPI
DWORD
WINAPI
RtlRunOnceComplete(
    PRTL_RUN_ONCE,
    DWORD,
    PVOID);

#endif

#define RTL_CONDITION_VARIABLE_INIT {0}
#define RTL_CONDITION_VARIABLE_LOCKMODE_SHARED 0x1

typedef struct _RTL_CONDITION_VARIABLE {
  PVOID Ptr;
} RTL_CONDITION_VARIABLE, *PRTL_CONDITION_VARIABLE;

typedef struct _RTL_CRITICAL_SECTION_DEBUG {
  WORD Type;
  WORD CreatorBackTraceIndex;
  struct _RTL_CRITICAL_SECTION *CriticalSection;
  LIST_ENTRY ProcessLocksList;
  DWORD EntryCount;
  DWORD ContentionCount;
  DWORD Flags;
  WORD CreatorBackTraceIndexHigh;
  WORD SpareWORD;
} RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG, RTL_RESOURCE_DEBUG, *PRTL_RESOURCE_DEBUG;

#include "pshpack8.h"
typedef struct _RTL_CRITICAL_SECTION {
  PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
  LONG LockCount;
  LONG RecursionCount;
  HANDLE OwningThread;
  HANDLE LockSemaphore;
  ULONG_PTR SpinCount;
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;
#include "poppack.h"

NTSYSAPI
WORD
NTAPI
RtlCaptureStackBackTrace(
    IN DWORD FramesToSkip,
    IN DWORD FramesToCapture,
    OUT PVOID *BackTrace,
    OUT PDWORD BackTraceHash OPTIONAL
);

NTSYSAPI
VOID
NTAPI
RtlCaptureContext(
    _Out_ PCONTEXT ContextRecord
);

NTSYSAPI
PVOID
NTAPI
RtlPcToFileHeader(
  _In_ PVOID PcValue,
  _Out_ PVOID* BaseOfImage);

NTSYSAPI
VOID
NTAPI
RtlUnwind(
    _In_opt_ PVOID TargetFrame,
    _In_opt_ PVOID TargetIp,
    _In_opt_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PVOID ReturnValue);

#define RTL_SRWLOCK_INIT {0}

typedef struct _RTL_SRWLOCK {
  PVOID Ptr;
} RTL_SRWLOCK, *PRTL_SRWLOCK;

typedef LONG
(NTAPI *PVECTORED_EXCEPTION_HANDLER)(
    struct _EXCEPTION_POINTERS *ExceptionInfo
);


#define EVENTLOG_SEQUENTIAL_READ    1
#define EVENTLOG_SEEK_READ          2
#define EVENTLOG_FORWARDS_READ      4
#define EVENTLOG_BACKWARDS_READ     8

#define EVENTLOG_SUCCESS            0
#define EVENTLOG_ERROR_TYPE         1
#define EVENTLOG_WARNING_TYPE       2
#define EVENTLOG_INFORMATION_TYPE   4
#define EVENTLOG_AUDIT_SUCCESS      8
#define EVENTLOG_AUDIT_FAILURE      16

typedef struct _EVENTLOGRECORD {
  DWORD Length;             /* Length of full record, including the data portion */
  DWORD Reserved;
  DWORD RecordNumber;
  DWORD TimeGenerated;
  DWORD TimeWritten;
  DWORD EventID;
  WORD EventType;
  WORD NumStrings;          /* Number of strings in the 'Strings' array */
  WORD EventCategory;
  WORD ReservedFlags;
  DWORD ClosingRecordNumber;
  DWORD StringOffset;
  DWORD UserSidLength;
  DWORD UserSidOffset;
  DWORD DataLength;         /* Length of the data portion */
  DWORD DataOffset;         /* Offset from beginning of record */
/*
 * Length-varying data:
 *
 * WCHAR SourceName[];
 * WCHAR ComputerName[];
 * SID   UserSid;           // Must be aligned on a DWORD boundary
 * WCHAR Strings[];
 * BYTE  Data[];
 * CHAR  Pad[];             // Padding for DWORD boundary
 * DWORD Length;            // Same as the first 'Length' member at the beginning
 */
} EVENTLOGRECORD, *PEVENTLOGRECORD;


typedef struct _OSVERSIONINFOA {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  CHAR szCSDVersion[128];
} OSVERSIONINFOA, *POSVERSIONINFOA, *LPOSVERSIONINFOA;

typedef struct _OSVERSIONINFOW {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  WCHAR szCSDVersion[128];
} OSVERSIONINFOW, *POSVERSIONINFOW, *LPOSVERSIONINFOW, RTL_OSVERSIONINFOW, *PRTL_OSVERSIONINFOW;

typedef struct _OSVERSIONINFOEXA {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  CHAR szCSDVersion[128];
  WORD wServicePackMajor;
  WORD wServicePackMinor;
  WORD wSuiteMask;
  BYTE wProductType;
  BYTE wReserved;
} OSVERSIONINFOEXA, *POSVERSIONINFOEXA, *LPOSVERSIONINFOEXA;

typedef struct _OSVERSIONINFOEXW {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  WCHAR szCSDVersion[128];
  WORD wServicePackMajor;
  WORD wServicePackMinor;
  WORD wSuiteMask;
  BYTE wProductType;
  BYTE wReserved;
} OSVERSIONINFOEXW, *POSVERSIONINFOEXW, *LPOSVERSIONINFOEXW, RTL_OSVERSIONINFOEXW, *PRTL_OSVERSIONINFOEXW;

#include <pshpack2.h>

typedef struct _IMAGE_VXD_HEADER {
  WORD e32_magic;
  BYTE e32_border;
  BYTE e32_worder;
  DWORD e32_level;
  WORD e32_cpu;
  WORD e32_os;
  DWORD e32_ver;
  DWORD e32_mflags;
  DWORD e32_mpages;
  DWORD e32_startobj;
  DWORD e32_eip;
  DWORD e32_stackobj;
  DWORD e32_esp;
  DWORD e32_pagesize;
  DWORD e32_lastpagesize;
  DWORD e32_fixupsize;
  DWORD e32_fixupsum;
  DWORD e32_ldrsize;
  DWORD e32_ldrsum;
  DWORD e32_objtab;
  DWORD e32_objcnt;
  DWORD e32_objmap;
  DWORD e32_itermap;
  DWORD e32_rsrctab;
  DWORD e32_rsrccnt;
  DWORD e32_restab;
  DWORD e32_enttab;
  DWORD e32_dirtab;
  DWORD e32_dircnt;
  DWORD e32_fpagetab;
  DWORD e32_frectab;
  DWORD e32_impmod;
  DWORD e32_impmodcnt;
  DWORD e32_impproc;
  DWORD e32_pagesum;
  DWORD e32_datapage;
  DWORD e32_preload;
  DWORD e32_nrestab;
  DWORD e32_cbnrestab;
  DWORD e32_nressum;
  DWORD e32_autodata;
  DWORD e32_debuginfo;
  DWORD e32_debuglen;
  DWORD e32_instpreload;
  DWORD e32_instdemand;
  DWORD e32_heapsize;
  BYTE e32_res3[12];
  DWORD e32_winresoff;
  DWORD e32_winreslen;
  WORD e32_devid;
  WORD e32_ddkver;
} IMAGE_VXD_HEADER, *PIMAGE_VXD_HEADER;

typedef struct _IMAGE_DOS_HEADER {
  WORD e_magic;
  WORD e_cblp;
  WORD e_cp;
  WORD e_crlc;
  WORD e_cparhdr;
  WORD e_minalloc;
  WORD e_maxalloc;
  WORD e_ss;
  WORD e_sp;
  WORD e_csum;
  WORD e_ip;
  WORD e_cs;
  WORD e_lfarlc;
  WORD e_ovno;
  WORD e_res[4];
  WORD e_oemid;
  WORD e_oeminfo;
  WORD e_res2[10];
  LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_OS2_HEADER {
  WORD ne_magic;
  CHAR ne_ver;
  CHAR ne_rev;
  WORD ne_enttab;
  WORD ne_cbenttab;
  LONG ne_crc;
  WORD ne_flags;
  WORD ne_autodata;
  WORD ne_heap;
  WORD ne_stack;
  LONG ne_csip;
  LONG ne_sssp;
  WORD ne_cseg;
  WORD ne_cmod;
  WORD ne_cbnrestab;
  WORD ne_segtab;
  WORD ne_rsrctab;
  WORD ne_restab;
  WORD ne_modtab;
  WORD ne_imptab;
  LONG ne_nrestab;
  WORD ne_cmovent;
  WORD ne_align;
  WORD ne_cres;
  BYTE ne_exetyp;
  BYTE ne_flagsothers;
  WORD ne_pretthunks;
  WORD ne_psegrefbytes;
  WORD ne_swaparea;
  WORD ne_expver;
} IMAGE_OS2_HEADER, *PIMAGE_OS2_HEADER;

#include <poppack.h>

typedef struct _IMAGE_FILE_HEADER {
  WORD Machine;
  WORD NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD SizeOfOptionalHeader;
  WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
  WORD Magic;
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  DWORD BaseOfData;
  DWORD ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  DWORD SizeOfStackReserve;
  DWORD SizeOfStackCommit;
  DWORD SizeOfHeapReserve;
  DWORD SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD Magic;
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  ULONGLONG ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  ULONGLONG SizeOfStackReserve;
  ULONGLONG SizeOfStackCommit;
  ULONGLONG SizeOfHeapReserve;
  ULONGLONG SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_ROM_OPTIONAL_HEADER {
  WORD Magic;
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  DWORD BaseOfData;
  DWORD BaseOfBss;
  DWORD GprMask;
  DWORD CprMask[4];
  DWORD GpValue;
} IMAGE_ROM_OPTIONAL_HEADER, *PIMAGE_ROM_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS32 {
  DWORD Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
  DWORD Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

#ifdef _WIN64
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER64 PIMAGE_OPTIONAL_HEADER;
typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
#else
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32 PIMAGE_OPTIONAL_HEADER;
typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
#endif

typedef struct _IMAGE_ROM_HEADERS {
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
} IMAGE_ROM_HEADERS, *PIMAGE_ROM_HEADERS;

typedef struct _IMAGE_SECTION_HEADER {
  BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD NumberOfRelocations;
  WORD NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#include <pshpack2.h>

typedef struct _IMAGE_SYMBOL {
  union {
    BYTE ShortName[8];
    struct {
      DWORD Short;
      DWORD Long;
    } Name;
    PBYTE LongName[2];
  } N;
  DWORD Value;
  SHORT SectionNumber;
  WORD Type;
  BYTE StorageClass;
  BYTE NumberOfAuxSymbols;
} IMAGE_SYMBOL, *PIMAGE_SYMBOL;

typedef struct _IMAGE_LINENUMBER {
  union {
    DWORD SymbolTableIndex;
    DWORD VirtualAddress;
  } Type;
  WORD Linenumber;
} IMAGE_LINENUMBER, UNALIGNED *PIMAGE_LINENUMBER;

typedef struct IMAGE_AUX_SYMBOL_TOKEN_DEF {
  BYTE bAuxType;
  BYTE bReserved;
  DWORD SymbolTableIndex;
  BYTE rgbReserved[12];
} IMAGE_AUX_SYMBOL_TOKEN_DEF, UNALIGNED *PIMAGE_AUX_SYMBOL_TOKEN_DEF;

typedef union _IMAGE_AUX_SYMBOL {
  struct {
    DWORD TagIndex;
    union {
      struct {
        WORD Linenumber;
        WORD Size;
      } LnSz;
      DWORD TotalSize;
    } Misc;
    union {
      struct {
        DWORD PointerToLinenumber;
        DWORD PointerToNextFunction;
      } Function;
      struct {
        WORD Dimension[4];
      } Array;
    } FcnAry;
    WORD TvIndex;
  } Sym;
  struct {
    BYTE Name[IMAGE_SIZEOF_SYMBOL];
  } File;
  struct {
    DWORD Length;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD CheckSum;
    SHORT Number;
    BYTE Selection;
    BYTE bReserved;
    SHORT HighNumber;
  } Section;
  IMAGE_AUX_SYMBOL_TOKEN_DEF TokenDef;
  struct {
    DWORD crc;
    BYTE rgbReserved[14];
  } CRC;
} IMAGE_AUX_SYMBOL, *PIMAGE_AUX_SYMBOL;

typedef struct _IMAGE_RELOCATION {
  _ANONYMOUS_UNION union {
    DWORD VirtualAddress;
    DWORD RelocCount;
  } DUMMYUNIONNAME;
  DWORD SymbolTableIndex;
  WORD Type;
} IMAGE_RELOCATION, UNALIGNED *PIMAGE_RELOCATION;

#include <poppack.h>

#ifndef __IMAGE_COR20_HEADER_DEFINED__
#define __IMAGE_COR20_HEADER_DEFINED__

typedef enum ReplacesCorHdrNumericDefines {
  COMIMAGE_FLAGS_ILONLY = 0x00000001,
  COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002,
  COMIMAGE_FLAGS_IL_LIBRARY = 0x00000004,
  COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008,
  COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010,
  COMIMAGE_FLAGS_TRACKDEBUGDATA = 0x00010000,
  COMIMAGE_FLAGS_32BITPREFERRED = 0x00020000,
  COR_VERSION_MAJOR_V2 = 2,
  COR_VERSION_MAJOR = COR_VERSION_MAJOR_V2,
  COR_VERSION_MINOR = 0,
  COR_DELETED_NAME_LENGTH = 8,
  COR_VTABLEGAP_NAME_LENGTH = 8,
  NATIVE_TYPE_MAX_CB = 1,
  COR_ILMETHOD_SECT_SMALL_MAX_DATASIZE = 0xFF,
  IMAGE_COR_MIH_METHODRVA = 0x01,
  IMAGE_COR_MIH_EHRVA = 0x02,
  IMAGE_COR_MIH_BASICBLOCK = 0x08,
  COR_VTABLE_32BIT = 0x01,
  COR_VTABLE_64BIT = 0x02,
  COR_VTABLE_FROM_UNMANAGED = 0x04,
  COR_VTABLE_FROM_UNMANAGED_RETAIN_APPDOMAIN = 0x08,
  COR_VTABLE_CALL_MOST_DERIVED = 0x10,
  IMAGE_COR_EATJ_THUNK_SIZE = 32,
  MAX_CLASS_NAME = 1024,
  MAX_PACKAGE_NAME = 1024
} ReplacesCorHdrNumericDefines;

typedef struct IMAGE_COR20_HEADER {
  DWORD cb;
  WORD MajorRuntimeVersion;
  WORD MinorRuntimeVersion;
  IMAGE_DATA_DIRECTORY MetaData;
  DWORD Flags;
  _ANONYMOUS_UNION union {
    DWORD EntryPointToken;
    DWORD EntryPointRVA;
  } DUMMYUNIONNAME;
  IMAGE_DATA_DIRECTORY Resources;
  IMAGE_DATA_DIRECTORY StrongNameSignature;
  IMAGE_DATA_DIRECTORY CodeManagerTable;
  IMAGE_DATA_DIRECTORY VTableFixups;
  IMAGE_DATA_DIRECTORY ExportAddressTableJumps;
  IMAGE_DATA_DIRECTORY ManagedNativeHeader;
} IMAGE_COR20_HEADER, *PIMAGE_COR20_HEADER;

#endif /* __IMAGE_COR20_HEADER_DEFINED__ */

typedef struct _IMAGE_COFF_SYMBOLS_HEADER {
  DWORD NumberOfSymbols;
  DWORD LvaToFirstSymbol;
  DWORD NumberOfLinenumbers;
  DWORD LvaToFirstLinenumber;
  DWORD RvaToFirstByteOfCode;
  DWORD RvaToLastByteOfCode;
  DWORD RvaToFirstByteOfData;
  DWORD RvaToLastByteOfData;
} IMAGE_COFF_SYMBOLS_HEADER, *PIMAGE_COFF_SYMBOLS_HEADER;

typedef struct _IMAGE_BASE_RELOCATION {
  DWORD VirtualAddress;
  DWORD SizeOfBlock;
} IMAGE_BASE_RELOCATION, UNALIGNED *PIMAGE_BASE_RELOCATION;

typedef struct _IMAGE_ARCHIVE_MEMBER_HEADER {
  BYTE Name[16];
  BYTE Date[12];
  BYTE UserID[6];
  BYTE GroupID[6];
  BYTE Mode[8];
  BYTE Size[10];
  BYTE EndHeader[2];
} IMAGE_ARCHIVE_MEMBER_HEADER, *PIMAGE_ARCHIVE_MEMBER_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY {
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD Name;
  DWORD Base;
  DWORD NumberOfFunctions;
  DWORD NumberOfNames;
  DWORD AddressOfFunctions;
  DWORD AddressOfNames;
  DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_IMPORT_BY_NAME {
  WORD Hint;
  BYTE Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

#include <pshpack8.h>
typedef struct _IMAGE_THUNK_DATA64 {
  union {
    ULONGLONG ForwarderString;
    ULONGLONG Function;
    ULONGLONG Ordinal;
    ULONGLONG AddressOfData;
  } u1;
} IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;
#include <poppack.h>

typedef struct _IMAGE_THUNK_DATA32 {
  union {
    DWORD ForwarderString;
    DWORD Function;
    DWORD Ordinal;
    DWORD AddressOfData;
  } u1;
} IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL
#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64)!=0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32)!=0)

typedef VOID
(NTAPI *PIMAGE_TLS_CALLBACK)(PVOID DllHandle,DWORD Reason,PVOID Reserved);

typedef struct _IMAGE_TLS_DIRECTORY64 {
  ULONGLONG StartAddressOfRawData;
  ULONGLONG EndAddressOfRawData;
  ULONGLONG AddressOfIndex;
  ULONGLONG AddressOfCallBacks;
  DWORD SizeOfZeroFill;
  DWORD Characteristics;
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;

typedef struct _IMAGE_TLS_DIRECTORY32 {
  DWORD StartAddressOfRawData;
  DWORD EndAddressOfRawData;
  DWORD AddressOfIndex;
  DWORD AddressOfCallBacks;
  DWORD SizeOfZeroFill;
  DWORD Characteristics;
} IMAGE_TLS_DIRECTORY32, *PIMAGE_TLS_DIRECTORY32;

#ifdef _WIN64
#define IMAGE_ORDINAL_FLAG IMAGE_ORDINAL_FLAG64
#define IMAGE_ORDINAL(Ordinal) IMAGE_ORDINAL64(Ordinal)
typedef IMAGE_THUNK_DATA64 IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA64 PIMAGE_THUNK_DATA;
#define IMAGE_SNAP_BY_ORDINAL(Ordinal) IMAGE_SNAP_BY_ORDINAL64(Ordinal)
typedef IMAGE_TLS_DIRECTORY64 IMAGE_TLS_DIRECTORY;
typedef PIMAGE_TLS_DIRECTORY64 PIMAGE_TLS_DIRECTORY;
#else
#define IMAGE_ORDINAL_FLAG IMAGE_ORDINAL_FLAG32
#define IMAGE_ORDINAL(Ordinal) IMAGE_ORDINAL32(Ordinal)
typedef IMAGE_THUNK_DATA32 IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA32 PIMAGE_THUNK_DATA;
#define IMAGE_SNAP_BY_ORDINAL(Ordinal) IMAGE_SNAP_BY_ORDINAL32(Ordinal)
typedef IMAGE_TLS_DIRECTORY32 IMAGE_TLS_DIRECTORY;
typedef PIMAGE_TLS_DIRECTORY32 PIMAGE_TLS_DIRECTORY;
#endif

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
  _ANONYMOUS_UNION union {
    DWORD Characteristics;
    DWORD OriginalFirstThunk;
  } DUMMYUNIONNAME;
  DWORD TimeDateStamp;
  DWORD ForwarderChain;
  DWORD Name;
  DWORD FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR, UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
  DWORD TimeDateStamp;
  WORD OffsetModuleName;
  WORD NumberOfModuleForwarderRefs;
} IMAGE_BOUND_IMPORT_DESCRIPTOR, *PIMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_BOUND_FORWARDER_REF {
  DWORD TimeDateStamp;
  WORD OffsetModuleName;
  WORD Reserved;
} IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;

typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR {
  union {
    DWORD AllAttributes;
    struct {
      DWORD RvaBased:1;
      DWORD ReservedAttributes:31;
    };
  } Attributes;
  DWORD DllNameRVA;
  DWORD ModuleHandleRVA;
  DWORD ImportAddressTableRVA;
  DWORD ImportNameTableRVA;
  DWORD BoundImportAddressTableRVA;
  DWORD UnloadInformationTableRVA;
  DWORD TimeDateStamp;
} IMAGE_DELAYLOAD_DESCRIPTOR, *PIMAGE_DELAYLOAD_DESCRIPTOR;

typedef const IMAGE_DELAYLOAD_DESCRIPTOR *PCIMAGE_DELAYLOAD_DESCRIPTOR;

typedef struct _IMAGE_RESOURCE_DIRECTORY {
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  WORD NumberOfNamedEntries;
  WORD NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
  _ANONYMOUS_UNION union {
    _ANONYMOUS_STRUCT struct {
      DWORD NameOffset:31;
      DWORD NameIsString:1;
    } DUMMYSTRUCTNAME;
    DWORD Name;
    WORD Id;
  } DUMMYUNIONNAME;
  _ANONYMOUS_UNION union {
    DWORD OffsetToData;
    _ANONYMOUS_STRUCT struct {
      DWORD OffsetToDirectory:31;
      DWORD DataIsDirectory:1;
    } DUMMYSTRUCTNAME2;
  } DUMMYUNIONNAME2;
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_STRING {
  WORD Length;
  CHAR NameString[1];
} IMAGE_RESOURCE_DIRECTORY_STRING, *PIMAGE_RESOURCE_DIRECTORY_STRING;

typedef struct _IMAGE_RESOURCE_DIR_STRING_U {
  WORD Length;
  WCHAR NameString[1];
} IMAGE_RESOURCE_DIR_STRING_U, *PIMAGE_RESOURCE_DIR_STRING_U;

typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
  DWORD OffsetToData;
  DWORD Size;
  DWORD CodePage;
  DWORD Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY32 {
  DWORD Size;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD GlobalFlagsClear;
  DWORD GlobalFlagsSet;
  DWORD CriticalSectionDefaultTimeout;
  DWORD DeCommitFreeBlockThreshold;
  DWORD DeCommitTotalFreeThreshold;
  DWORD LockPrefixTable;
  DWORD MaximumAllocationSize;
  DWORD VirtualMemoryThreshold;
  DWORD ProcessHeapFlags;
  DWORD ProcessAffinityMask;
  WORD CSDVersion;
  WORD Reserved1;
  DWORD EditList;
  DWORD SecurityCookie;
  DWORD SEHandlerTable;
  DWORD SEHandlerCount;
} IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY64 {
  DWORD Size;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD GlobalFlagsClear;
  DWORD GlobalFlagsSet;
  DWORD CriticalSectionDefaultTimeout;
  ULONGLONG DeCommitFreeBlockThreshold;
  ULONGLONG DeCommitTotalFreeThreshold;
  ULONGLONG LockPrefixTable;
  ULONGLONG MaximumAllocationSize;
  ULONGLONG VirtualMemoryThreshold;
  ULONGLONG ProcessAffinityMask;
  DWORD ProcessHeapFlags;
  WORD CSDVersion;
  WORD Reserved1;
  ULONGLONG EditList;
  ULONGLONG SecurityCookie;
  ULONGLONG SEHandlerTable;
  ULONGLONG SEHandlerCount;
} IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

#ifdef _WIN64
typedef IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_DIRECTORY;
typedef PIMAGE_LOAD_CONFIG_DIRECTORY64 PIMAGE_LOAD_CONFIG_DIRECTORY;
#else
typedef IMAGE_LOAD_CONFIG_DIRECTORY32 IMAGE_LOAD_CONFIG_DIRECTORY;
typedef PIMAGE_LOAD_CONFIG_DIRECTORY32 PIMAGE_LOAD_CONFIG_DIRECTORY;
#endif

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
  DWORD BeginAddress;
  DWORD EndAddress;
  DWORD UnwindInfoAddress;
} IMAGE_RUNTIME_FUNCTION_ENTRY, *PIMAGE_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_DEBUG_DIRECTORY {
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD Type;
  DWORD SizeOfData;
  DWORD AddressOfRawData;
  DWORD PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

typedef struct _FPO_DATA {
  DWORD ulOffStart;
  DWORD cbProcSize;
  DWORD cdwLocals;
  WORD cdwParams;
  WORD cbProlog:8;
  WORD cbRegs:3;
  WORD fHasSEH:1;
  WORD fUseBP:1;
  WORD reserved:1;
  WORD cbFrame:2;
} FPO_DATA, *PFPO_DATA;

typedef struct _IMAGE_DEBUG_MISC {
  DWORD DataType;
  DWORD Length;
  BOOLEAN Unicode;
  BYTE Reserved[3];
  BYTE Data[1];
} IMAGE_DEBUG_MISC, *PIMAGE_DEBUG_MISC;

typedef struct _IMAGE_FUNCTION_ENTRY {
  DWORD StartingAddress;
  DWORD EndingAddress;
  DWORD EndOfPrologue;
} IMAGE_FUNCTION_ENTRY, *PIMAGE_FUNCTION_ENTRY;

typedef struct _IMAGE_SEPARATE_DEBUG_HEADER {
  WORD Signature;
  WORD Flags;
  WORD Machine;
  WORD Characteristics;
  DWORD TimeDateStamp;
  DWORD CheckSum;
  DWORD ImageBase;
  DWORD SizeOfImage;
  DWORD NumberOfSections;
  DWORD ExportedNamesSize;
  DWORD DebugDirectorySize;
  DWORD SectionAlignment;
  DWORD Reserved[2];
} IMAGE_SEPARATE_DEBUG_HEADER, *PIMAGE_SEPARATE_DEBUG_HEADER;

typedef enum _CM_SERVICE_NODE_TYPE {
  DriverType = SERVICE_KERNEL_DRIVER,
  FileSystemType = SERVICE_FILE_SYSTEM_DRIVER,
  Win32ServiceOwnProcess = SERVICE_WIN32_OWN_PROCESS,
  Win32ServiceShareProcess = SERVICE_WIN32_SHARE_PROCESS,
  AdapterType = SERVICE_ADAPTER,
  RecognizerType = SERVICE_RECOGNIZER_DRIVER
} SERVICE_NODE_TYPE;

typedef enum _CM_SERVICE_LOAD_TYPE {
  BootLoad = SERVICE_BOOT_START,
  SystemLoad = SERVICE_SYSTEM_START,
  AutoLoad = SERVICE_AUTO_START,
  DemandLoad = SERVICE_DEMAND_START,
  DisableLoad = SERVICE_DISABLED
} SERVICE_LOAD_TYPE;

typedef enum _CM_ERROR_CONTROL_TYPE {
  IgnoreError = SERVICE_ERROR_IGNORE,
  NormalError = SERVICE_ERROR_NORMAL,
  SevereError = SERVICE_ERROR_SEVERE,
  CriticalError = SERVICE_ERROR_CRITICAL
} SERVICE_ERROR_TYPE;

typedef struct _NT_TIB {
  struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
  PVOID StackBase;
  PVOID StackLimit;
  PVOID SubSystemTib;
  _ANONYMOUS_UNION union {
    PVOID FiberData;
    DWORD Version;
  } DUMMYUNIONNAME;
  PVOID ArbitraryUserPointer;
  struct _NT_TIB *Self;
} NT_TIB,*PNT_TIB;

typedef struct _NT_TIB32 {
  DWORD ExceptionList;
  DWORD StackBase;
  DWORD StackLimit;
  DWORD SubSystemTib;
  _ANONYMOUS_UNION union {
    DWORD FiberData;
    DWORD Version;
  } DUMMYUNIONNAME;
  DWORD ArbitraryUserPointer;
  DWORD Self;
} NT_TIB32,*PNT_TIB32;

typedef struct _NT_TIB64 {
  DWORD64 ExceptionList;
  DWORD64 StackBase;
  DWORD64 StackLimit;
  DWORD64 SubSystemTib;
  _ANONYMOUS_UNION union {
    DWORD64 FiberData;
    DWORD Version;
  } DUMMYUNIONNAME;
  DWORD64 ArbitraryUserPointer;
  DWORD64 Self;
} NT_TIB64,*PNT_TIB64;

typedef struct _REPARSE_GUID_DATA_BUFFER {
  DWORD ReparseTag;
  WORD ReparseDataLength;
  WORD Reserved;
  GUID ReparseGuid;
  struct {
    BYTE DataBuffer[1];
  } GenericReparseBuffer;
} REPARSE_GUID_DATA_BUFFER, *PREPARSE_GUID_DATA_BUFFER;

typedef struct _REPARSE_POINT_INFORMATION {
    WORD   ReparseDataLength;
    WORD   UnparsedNameLength;
} REPARSE_POINT_INFORMATION, *PREPARSE_POINT_INFORMATION;

typedef union _FILE_SEGMENT_ELEMENT {
  PVOID64 Buffer;
  ULONGLONG Alignment;
} FILE_SEGMENT_ELEMENT, *PFILE_SEGMENT_ELEMENT;

/* JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags constants */
#define JOB_OBJECT_LIMIT_WORKINGSET                 0x0001
#define JOB_OBJECT_LIMIT_PROCESS_TIME               0x0002
#define JOB_OBJECT_LIMIT_JOB_TIME                   0x0004
#define JOB_OBJECT_LIMIT_ACTIVE_PROCESS             0x0008
#define JOB_OBJECT_LIMIT_AFFINITY                   0x0010
#define JOB_OBJECT_LIMIT_PRIORITY_CLASS             0x0020
#define JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME          0x0040
#define JOB_OBJECT_LIMIT_SCHEDULING_CLASS           0x0080
#define JOB_OBJECT_LIMIT_PROCESS_MEMORY             0x0100
#define JOB_OBJECT_LIMIT_JOB_MEMORY                 0x0200
#define JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION 0x0400
#define JOB_OBJECT_LIMIT_BREAKAWAY_OK               0x0800
#define JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK        0x1000
#define JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE          0x2000

/* JOBOBJECT_BASIC_UI_RESTRICTIONS.UIRestrictionsClass constants */
#define JOB_OBJECT_UILIMIT_HANDLES          0x0001
#define JOB_OBJECT_UILIMIT_READCLIPBOARD    0x0002
#define JOB_OBJECT_UILIMIT_WRITECLIPBOARD   0x0004
#define JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS 0x0008
#define JOB_OBJECT_UILIMIT_DISPLAYSETTINGS  0x0010
#define JOB_OBJECT_UILIMIT_GLOBALATOMS      0x0020
#define JOB_OBJECT_UILIMIT_DESKTOP          0x0040
#define JOB_OBJECT_UILIMIT_EXITWINDOWS      0x0080

/* JOBOBJECT_SECURITY_LIMIT_INFORMATION.SecurityLimitFlags constants */
#define JOB_OBJECT_SECURITY_NO_ADMIN          0x0001
#define JOB_OBJECT_SECURITY_RESTRICTED_TOKEN  0x0002
#define JOB_OBJECT_SECURITY_ONLY_TOKEN        0x0004
#define JOB_OBJECT_SECURITY_FILTER_TOKENS     0x0008

/* JOBOBJECT_END_OF_JOB_TIME_INFORMATION.EndOfJobTimeAction constants */
#define JOB_OBJECT_TERMINATE_AT_END_OF_JOB  0
#define JOB_OBJECT_POST_AT_END_OF_JOB       1

#define JOB_OBJECT_MSG_END_OF_JOB_TIME        1
#define JOB_OBJECT_MSG_END_OF_PROCESS_TIME    2
#define JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT   3
#define JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO    4
#define JOB_OBJECT_MSG_NEW_PROCESS            6
#define JOB_OBJECT_MSG_EXIT_PROCESS           7
#define JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS  8
#define JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT   9
#define JOB_OBJECT_MSG_JOB_MEMORY_LIMIT       10

#define JOB_OBJECT_ASSIGN_PROCESS           1
#define JOB_OBJECT_SET_ATTRIBUTES           2
#define JOB_OBJECT_QUERY                    4
#define JOB_OBJECT_TERMINATE                8
#define JOB_OBJECT_SET_SECURITY_ATTRIBUTES  16
#define JOB_OBJECT_ALL_ACCESS               (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|31)

typedef enum _JOBOBJECTINFOCLASS {
  JobObjectBasicAccountingInformation = 1,
  JobObjectBasicLimitInformation,
  JobObjectBasicProcessIdList,
  JobObjectBasicUIRestrictions,
  JobObjectSecurityLimitInformation,
  JobObjectEndOfJobTimeInformation,
  JobObjectAssociateCompletionPortInformation,
  JobObjectBasicAndIoAccountingInformation,
  JobObjectExtendedLimitInformation,
  JobObjectJobSetInformation,
  JobObjectGroupInformation,
  MaxJobObjectInfoClass
} JOBOBJECTINFOCLASS;

typedef struct _JOB_SET_ARRAY {
  HANDLE JobHandle;
  DWORD MemberLevel;
  DWORD Flags;
} JOB_SET_ARRAY, *PJOB_SET_ARRAY;

typedef struct _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
  LARGE_INTEGER TotalUserTime;
  LARGE_INTEGER TotalKernelTime;
  LARGE_INTEGER ThisPeriodTotalUserTime;
  LARGE_INTEGER ThisPeriodTotalKernelTime;
  DWORD TotalPageFaultCount;
  DWORD TotalProcesses;
  DWORD ActiveProcesses;
  DWORD TotalTerminatedProcesses;
} JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,*PJOBOBJECT_BASIC_ACCOUNTING_INFORMATION;

typedef struct _JOBOBJECT_BASIC_LIMIT_INFORMATION {
  LARGE_INTEGER PerProcessUserTimeLimit;
  LARGE_INTEGER PerJobUserTimeLimit;
  DWORD LimitFlags;
  SIZE_T MinimumWorkingSetSize;
  SIZE_T MaximumWorkingSetSize;
  DWORD ActiveProcessLimit;
  ULONG_PTR Affinity;
  DWORD PriorityClass;
  DWORD SchedulingClass;
} JOBOBJECT_BASIC_LIMIT_INFORMATION,*PJOBOBJECT_BASIC_LIMIT_INFORMATION;

typedef struct _JOBOBJECT_BASIC_PROCESS_ID_LIST {
  DWORD NumberOfAssignedProcesses;
  DWORD NumberOfProcessIdsInList;
  ULONG_PTR ProcessIdList[1];
} JOBOBJECT_BASIC_PROCESS_ID_LIST, *PJOBOBJECT_BASIC_PROCESS_ID_LIST;

typedef struct _JOBOBJECT_BASIC_UI_RESTRICTIONS {
  DWORD UIRestrictionsClass;
} JOBOBJECT_BASIC_UI_RESTRICTIONS,*PJOBOBJECT_BASIC_UI_RESTRICTIONS;

typedef struct _JOBOBJECT_SECURITY_LIMIT_INFORMATION {
  DWORD SecurityLimitFlags;
  HANDLE JobToken;
  PTOKEN_GROUPS SidsToDisable;
  PTOKEN_PRIVILEGES PrivilegesToDelete;
  PTOKEN_GROUPS RestrictedSids;
} JOBOBJECT_SECURITY_LIMIT_INFORMATION,*PJOBOBJECT_SECURITY_LIMIT_INFORMATION;

typedef struct _JOBOBJECT_END_OF_JOB_TIME_INFORMATION {
  DWORD EndOfJobTimeAction;
} JOBOBJECT_END_OF_JOB_TIME_INFORMATION,*PJOBOBJECT_END_OF_JOB_TIME_INFORMATION;

typedef struct _JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
  PVOID CompletionKey;
  HANDLE CompletionPort;
} JOBOBJECT_ASSOCIATE_COMPLETION_PORT,*PJOBOBJECT_ASSOCIATE_COMPLETION_PORT;

typedef struct _JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION {
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION BasicInfo;
  IO_COUNTERS IoInfo;
} JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION,*PJOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION;

typedef struct _JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
  JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
  IO_COUNTERS IoInfo;
  SIZE_T ProcessMemoryLimit;
  SIZE_T JobMemoryLimit;
  SIZE_T PeakProcessMemoryUsed;
  SIZE_T PeakJobMemoryUsed;
} JOBOBJECT_EXTENDED_LIMIT_INFORMATION,*PJOBOBJECT_EXTENDED_LIMIT_INFORMATION;

typedef struct _JOBOBJECT_JOBSET_INFORMATION {
  DWORD MemberLevel;
} JOBOBJECT_JOBSET_INFORMATION,*PJOBOBJECT_JOBSET_INFORMATION;

/* Fixme: Making these defines conditional on WINVER will break ddk includes */
#if 1 /* (WINVER >= 0x0500) */

#define ES_SYSTEM_REQUIRED                0x00000001
#define ES_DISPLAY_REQUIRED               0x00000002
#define ES_USER_PRESENT                   0x00000004
#define ES_CONTINUOUS                     0x80000000

typedef enum _LATENCY_TIME {
  LT_DONT_CARE,
  LT_LOWEST_LATENCY
} LATENCY_TIME, *PLATENCY_TIME;

typedef enum _SYSTEM_POWER_STATE {
  PowerSystemUnspecified = 0,
  PowerSystemWorking,
  PowerSystemSleeping1,
  PowerSystemSleeping2,
  PowerSystemSleeping3,
  PowerSystemHibernate,
  PowerSystemShutdown,
  PowerSystemMaximum
} SYSTEM_POWER_STATE, *PSYSTEM_POWER_STATE;

#define POWER_SYSTEM_MAXIMUM PowerSystemMaximum

typedef enum {
  PowerActionNone = 0,
  PowerActionReserved,
  PowerActionSleep,
  PowerActionHibernate,
  PowerActionShutdown,
  PowerActionShutdownReset,
  PowerActionShutdownOff,
  PowerActionWarmEject
} POWER_ACTION, *PPOWER_ACTION;

typedef enum _DEVICE_POWER_STATE {
  PowerDeviceUnspecified = 0,
  PowerDeviceD0,
  PowerDeviceD1,
  PowerDeviceD2,
  PowerDeviceD3,
  PowerDeviceMaximum
} DEVICE_POWER_STATE, *PDEVICE_POWER_STATE;

#if (NTDDI_VERSION >= NTDDI_WINXP) || !defined(_BATCLASS_)
typedef struct {
  DWORD Granularity;
  DWORD Capacity;
} BATTERY_REPORTING_SCALE, *PBATTERY_REPORTING_SCALE;
#endif

typedef struct _POWER_ACTION_POLICY {
  POWER_ACTION Action;
  DWORD Flags;
  DWORD EventCode;
} POWER_ACTION_POLICY, *PPOWER_ACTION_POLICY;

/* POWER_ACTION_POLICY.Flags constants */
#define POWER_ACTION_QUERY_ALLOWED        0x00000001
#define POWER_ACTION_UI_ALLOWED           0x00000002
#define POWER_ACTION_OVERRIDE_APPS        0x00000004
#define POWER_ACTION_LIGHTEST_FIRST       0x10000000
#define POWER_ACTION_LOCK_CONSOLE         0x20000000
#define POWER_ACTION_DISABLE_WAKES        0x40000000
#define POWER_ACTION_CRITICAL             0x80000000

/* POWER_ACTION_POLICY.EventCode constants */
#define POWER_LEVEL_USER_NOTIFY_TEXT      0x00000001
#define POWER_LEVEL_USER_NOTIFY_SOUND     0x00000002
#define POWER_LEVEL_USER_NOTIFY_EXEC      0x00000004
#define POWER_USER_NOTIFY_BUTTON          0x00000008
#define POWER_USER_NOTIFY_SHUTDOWN        0x00000010
#define POWER_FORCE_TRIGGER_RESET         0x80000000

#define DISCHARGE_POLICY_CRITICAL    0
#define DISCHARGE_POLICY_LOW        1
#define NUM_DISCHARGE_POLICIES        4

#define PO_THROTTLE_NONE    0
#define PO_THROTTLE_CONSTANT    1
#define PO_THROTTLE_DEGRADE    2
#define PO_THROTTLE_ADAPTIVE    3
#define PO_THROTTLE_MAXIMUM    4

typedef struct _SYSTEM_POWER_LEVEL {
  BOOLEAN Enable;
  BYTE Spare[3];
  DWORD BatteryLevel;
  POWER_ACTION_POLICY PowerPolicy;
  SYSTEM_POWER_STATE MinSystemState;
} SYSTEM_POWER_LEVEL, *PSYSTEM_POWER_LEVEL;

typedef struct _SYSTEM_POWER_POLICY {
  DWORD Revision;
  POWER_ACTION_POLICY PowerButton;
  POWER_ACTION_POLICY SleepButton;
  POWER_ACTION_POLICY LidClose;
  SYSTEM_POWER_STATE LidOpenWake;
  DWORD Reserved;
  POWER_ACTION_POLICY Idle;
  DWORD IdleTimeout;
  BYTE IdleSensitivity;
  BYTE DynamicThrottle;
  BYTE Spare2[2];
  SYSTEM_POWER_STATE MinSleep;
  SYSTEM_POWER_STATE MaxSleep;
  SYSTEM_POWER_STATE ReducedLatencySleep;
  DWORD WinLogonFlags;
  DWORD Spare3;
  DWORD DozeS4Timeout;
  DWORD BroadcastCapacityResolution;
  SYSTEM_POWER_LEVEL DischargePolicy[NUM_DISCHARGE_POLICIES];
  DWORD VideoTimeout;
  BOOLEAN VideoDimDisplay;
  DWORD VideoReserved[3];
  DWORD SpindownTimeout;
  BOOLEAN OptimizeForPower;
  BYTE FanThrottleTolerance;
  BYTE ForcedThrottle;
  BYTE MinThrottle;
  POWER_ACTION_POLICY OverThrottled;
} SYSTEM_POWER_POLICY, *PSYSTEM_POWER_POLICY;

typedef struct _SYSTEM_POWER_CAPABILITIES {
  BOOLEAN PowerButtonPresent;
  BOOLEAN SleepButtonPresent;
  BOOLEAN LidPresent;
  BOOLEAN SystemS1;
  BOOLEAN SystemS2;
  BOOLEAN SystemS3;
  BOOLEAN SystemS4;
  BOOLEAN SystemS5;
  BOOLEAN HiberFilePresent;
  BOOLEAN FullWake;
  BOOLEAN VideoDimPresent;
  BOOLEAN ApmPresent;
  BOOLEAN UpsPresent;
  BOOLEAN ThermalControl;
  BOOLEAN ProcessorThrottle;
  BYTE ProcessorMinThrottle;
#if (NTDDI_VERSION < NTDDI_WINXP)
  BYTE ProcessorThrottleScale;
  BYTE spare2[4];
#else
  BYTE ProcessorMaxThrottle;
  BOOLEAN FastSystemS4;
  BYTE spare2[3];
#endif /* (NTDDI_VERSION < NTDDI_WINXP) */
  BOOLEAN DiskSpinDown;
  BYTE spare3[8];
  BOOLEAN SystemBatteriesPresent;
  BOOLEAN BatteriesAreShortTerm;
  BATTERY_REPORTING_SCALE BatteryScale[3];
  SYSTEM_POWER_STATE AcOnLineWake;
  SYSTEM_POWER_STATE SoftLidWake;
  SYSTEM_POWER_STATE RtcWake;
  SYSTEM_POWER_STATE MinDeviceWakeState;
  SYSTEM_POWER_STATE DefaultLowLatencyWake;
} SYSTEM_POWER_CAPABILITIES, *PSYSTEM_POWER_CAPABILITIES;

typedef struct _SYSTEM_BATTERY_STATE {
  BOOLEAN AcOnLine;
  BOOLEAN BatteryPresent;
  BOOLEAN Charging;
  BOOLEAN Discharging;
  BOOLEAN Spare1[4];
  DWORD MaxCapacity;
  DWORD RemainingCapacity;
  DWORD Rate;
  DWORD EstimatedTime;
  DWORD DefaultAlert1;
  DWORD DefaultAlert2;
} SYSTEM_BATTERY_STATE, *PSYSTEM_BATTERY_STATE;

// FIXME: This should not be here!
typedef struct _PROCESSOR_POWER_INFORMATION {
  ULONG Number;
  ULONG MaxMhz;
  ULONG CurrentMhz;
  ULONG MhzLimit;
  ULONG MaxIdleState;
  ULONG CurrentIdleState;
} PROCESSOR_POWER_INFORMATION, *PPROCESSOR_POWER_INFORMATION;

typedef DWORD EXECUTION_STATE, *PEXECUTION_STATE;

typedef enum _POWER_INFORMATION_LEVEL {
  SystemPowerPolicyAc,
  SystemPowerPolicyDc,
  VerifySystemPolicyAc,
  VerifySystemPolicyDc,
  SystemPowerCapabilities,
  SystemBatteryState,
  SystemPowerStateHandler,
  ProcessorStateHandler,
  SystemPowerPolicyCurrent,
  AdministratorPowerPolicy,
  SystemReserveHiberFile,
  ProcessorInformation,
  SystemPowerInformation,
  ProcessorStateHandler2,
  LastWakeTime,
  LastSleepTime,
  SystemExecutionState,
  SystemPowerStateNotifyHandler,
  ProcessorPowerPolicyAc,
  ProcessorPowerPolicyDc,
  VerifyProcessorPowerPolicyAc,
  VerifyProcessorPowerPolicyDc,
  ProcessorPowerPolicyCurrent,
  SystemPowerStateLogging,
  SystemPowerLoggingEntry,
  SetPowerSettingValue,
  NotifyUserPowerSetting,
  PowerInformationLevelUnused0,
  PowerInformationLevelUnused1,
  SystemVideoState,
  TraceApplicationPowerMessage,
  TraceApplicationPowerMessageEnd,
  ProcessorPerfStates,
  ProcessorIdleStates,
  ProcessorCap,
  SystemWakeSource,
  SystemHiberFileInformation,
  TraceServicePowerMessage,
  ProcessorLoad,
  PowerShutdownNotification,
  MonitorCapabilities,
  SessionPowerInit,
  SessionDisplayState,
  PowerRequestCreate,
  PowerRequestAction,
  GetPowerRequestList,
  ProcessorInformationEx,
  NotifyUserModeLegacyPowerEvent,
  GroupPark,
  ProcessorIdleDomains,
  WakeTimerList,
  SystemHiberFileSize,
  PowerInformationLevelMaximum
} POWER_INFORMATION_LEVEL;

#if (_WIN32_WINNT >= 0x0501)

typedef enum _ACTIVATION_CONTEXT_INFO_CLASS {
  ActivationContextBasicInformation = 1,
  ActivationContextDetailedInformation = 2,
  AssemblyDetailedInformationInActivationContext = 3,
  FileInformationInAssemblyOfAssemblyInActivationContext = 4,
  RunlevelInformationInActivationContext = 5,
  CompatibilityInformationInActivationContext = 6,
  ActivationContextManifestResourceName = 7,
  MaxActivationContextInfoClass,
/* For compatibility with the old names */
  AssemblyDetailedInformationInActivationContxt = 3,
  FileInformationInAssemblyOfAssemblyInActivationContxt = 4
} ACTIVATION_CONTEXT_INFO_CLASS;

typedef struct _ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION {
  DWORD ulFlags;
  DWORD ulEncodedAssemblyIdentityLength;
  DWORD ulManifestPathType;
  DWORD ulManifestPathLength;
  LARGE_INTEGER liManifestLastWriteTime;
  DWORD ulPolicyPathType;
  DWORD ulPolicyPathLength;
  LARGE_INTEGER liPolicyLastWriteTime;
  DWORD ulMetadataSatelliteRosterIndex;
  DWORD ulManifestVersionMajor;
  DWORD ulManifestVersionMinor;
  DWORD ulPolicyVersionMajor;
  DWORD ulPolicyVersionMinor;
  DWORD ulAssemblyDirectoryNameLength;
  PCWSTR lpAssemblyEncodedAssemblyIdentity;
  PCWSTR lpAssemblyManifestPath;
  PCWSTR lpAssemblyPolicyPath;
  PCWSTR lpAssemblyDirectoryName;
  DWORD ulFileCount;
} ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION, *PACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION;
typedef const ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION *PCACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION;

typedef struct _ACTIVATION_CONTEXT_DETAILED_INFORMATION {
  DWORD dwFlags;
  DWORD ulFormatVersion;
  DWORD ulAssemblyCount;
  DWORD ulRootManifestPathType;
  DWORD ulRootManifestPathChars;
  DWORD ulRootConfigurationPathType;
  DWORD ulRootConfigurationPathChars;
  DWORD ulAppDirPathType;
  DWORD ulAppDirPathChars;
  PCWSTR lpRootManifestPath;
  PCWSTR lpRootConfigurationPath;
  PCWSTR lpAppDirPath;
} ACTIVATION_CONTEXT_DETAILED_INFORMATION, *PACTIVATION_CONTEXT_DETAILED_INFORMATION;
typedef const ACTIVATION_CONTEXT_DETAILED_INFORMATION *PCACTIVATION_CONTEXT_DETAILED_INFORMATION;

typedef struct _ACTIVATION_CONTEXT_QUERY_INDEX {
  DWORD ulAssemblyIndex;
  DWORD ulFileIndexInAssembly;
} ACTIVATION_CONTEXT_QUERY_INDEX,*PACTIVATION_CONTEXT_QUERY_INDEX;
typedef const ACTIVATION_CONTEXT_QUERY_INDEX *PCACTIVATION_CONTEXT_QUERY_INDEX;

typedef struct _ASSEMBLY_FILE_DETAILED_INFORMATION {
  DWORD ulFlags;
  DWORD ulFilenameLength;
  DWORD ulPathLength;
  PCWSTR lpFileName;
  PCWSTR lpFilePath;
} ASSEMBLY_FILE_DETAILED_INFORMATION,*PASSEMBLY_FILE_DETAILED_INFORMATION;
typedef const ASSEMBLY_FILE_DETAILED_INFORMATION *PCASSEMBLY_FILE_DETAILED_INFORMATION;

typedef enum {
  ACTCTX_RUN_LEVEL_UNSPECIFIED = 0,
  ACTCTX_RUN_LEVEL_AS_INVOKER,
  ACTCTX_RUN_LEVEL_HIGHEST_AVAILABLE,
  ACTCTX_RUN_LEVEL_REQUIRE_ADMIN,
  ACTCTX_RUN_LEVEL_NUMBERS
} ACTCTX_REQUESTED_RUN_LEVEL;

typedef struct _ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION {
  DWORD ulFlags;
  ACTCTX_REQUESTED_RUN_LEVEL RunLevel;
  DWORD UiAccess;
} ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION, *PACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION;

typedef enum {
  ACTCTX_COMPATIBILITY_ELEMENT_TYPE_UNKNOWN = 0,
  ACTCTX_COMPATIBILITY_ELEMENT_TYPE_OS
} ACTCTX_COMPATIBILITY_ELEMENT_TYPE;

typedef struct _COMPATIBILITY_CONTEXT_ELEMENT {
  GUID Id;
  ACTCTX_COMPATIBILITY_ELEMENT_TYPE Type;
} COMPATIBILITY_CONTEXT_ELEMENT, *PCOMPATIBILITY_CONTEXT_ELEMENT;

typedef struct _ACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION {
  DWORD ElementCount;
  COMPATIBILITY_CONTEXT_ELEMENT Elements[];
} ACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION, *PACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION;


#define ACTIVATION_CONTEXT_PATH_TYPE_NONE         1
#define ACTIVATION_CONTEXT_PATH_TYPE_WIN32_FILE   2
#define ACTIVATION_CONTEXT_PATH_TYPE_URL          3
#define ACTIVATION_CONTEXT_PATH_TYPE_ASSEMBLYREF  4

#define ACTIVATION_CONTEXT_SECTION_ASSEMBLY_INFORMATION          1
#define ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION               2
#define ACTIVATION_CONTEXT_SECTION_WINDOW_CLASS_REDIRECTION      3
#define ACTIVATION_CONTEXT_SECTION_COM_SERVER_REDIRECTION        4
#define ACTIVATION_CONTEXT_SECTION_COM_INTERFACE_REDIRECTION     5
#define ACTIVATION_CONTEXT_SECTION_COM_TYPE_LIBRARY_REDIRECTION  6
#define ACTIVATION_CONTEXT_SECTION_COM_PROGID_REDIRECTION        7
#define ACTIVATION_CONTEXT_SECTION_GLOBAL_OBJECT_RENAME_TABLE    8
#define ACTIVATION_CONTEXT_SECTION_CLR_SURROGATES                9

#endif /* (_WIN32_WINNT >= 0x0501) */

typedef struct _PROCESSOR_POWER_POLICY_INFO {
  DWORD TimeCheck;
  DWORD DemoteLimit;
  DWORD PromoteLimit;
  BYTE DemotePercent;
  BYTE PromotePercent;
  BYTE Spare[2];
  DWORD AllowDemotion:1;
  DWORD AllowPromotion:1;
  DWORD Reserved:30;
} PROCESSOR_POWER_POLICY_INFO, *PPROCESSOR_POWER_POLICY_INFO;

typedef struct _PROCESSOR_POWER_POLICY {
  DWORD Revision;
  BYTE DynamicThrottle;
  BYTE Spare[3];
  DWORD DisableCStates:1;
  DWORD Reserved:31;
  DWORD PolicyCount;
  PROCESSOR_POWER_POLICY_INFO Policy[3];
} PROCESSOR_POWER_POLICY, *PPROCESSOR_POWER_POLICY;

typedef struct _ADMINISTRATOR_POWER_POLICY {
  SYSTEM_POWER_STATE MinSleep;
  SYSTEM_POWER_STATE MaxSleep;
  DWORD MinVideoTimeout;
  DWORD MaxVideoTimeout;
  DWORD MinSpindownTimeout;
  DWORD MaxSpindownTimeout;
} ADMINISTRATOR_POWER_POLICY, *PADMINISTRATOR_POWER_POLICY;

#endif /* WINVER >= 0x0500 */

typedef VOID (NTAPI *WAITORTIMERCALLBACKFUNC)(PVOID,BOOLEAN);

#ifdef UNICODE
typedef OSVERSIONINFOW OSVERSIONINFO,*POSVERSIONINFO,*LPOSVERSIONINFO;
typedef OSVERSIONINFOEXW OSVERSIONINFOEX,*POSVERSIONINFOEX,*LPOSVERSIONINFOEX;
#else
typedef OSVERSIONINFOA OSVERSIONINFO,*POSVERSIONINFO,*LPOSVERSIONINFO;
typedef OSVERSIONINFOEXA OSVERSIONINFOEX,*POSVERSIONINFOEX,*LPOSVERSIONINFOEX;
#endif

#define VER_SET_CONDITION(lc,t,c) ((lc) = VerSetConditionMask((lc),(t),(c)))

#if (_WIN32_WINNT >= 0x0500)
ULONGLONG WINAPI VerSetConditionMask(_In_ ULONGLONG, _In_ DWORD, _In_ BYTE);
#endif

typedef enum _HEAP_INFORMATION_CLASS {
  HeapCompatibilityInformation,
  HeapEnableTerminationOnCorruption
} HEAP_INFORMATION_CLASS;

#define CACHE_FULLY_ASSOCIATIVE 0xFF

_Check_return_
NTSYSAPI
SIZE_T
NTAPI
RtlCompareMemory (
  _In_ const VOID *Source1,
  _In_ const VOID *Source2,
  _In_ SIZE_T Length);

#define RtlMoveMemory(Dest,Source,Length) memmove((Dest),(Source),(Length))
#define RtlCopyMemory(Dest,Source,Length) memcpy((Dest),(Source),(Length))
#define RtlFillMemory(Dest,Length,Fill) memset((Dest),(Fill),(Length))
#define RtlZeroMemory(Dest,Length) RtlFillMemory((Dest),(Length),0)
#define RtlEqualMemory(Dest,Source,Length) (!memcmp((Dest),(Source),(Length)))

FORCEINLINE
PVOID
RtlSecureZeroMemory(_Out_writes_bytes_all_(Length) PVOID Buffer,
                    _In_ SIZE_T Length)
{
    volatile char *VolatilePointer;

    /* Get a volatile pointer to prevent any compiler optimizations */
    VolatilePointer = (volatile char *)Buffer;

    /* Loop the whole buffer */
    while (Length)
    {
        /* Zero the current byte and move on */
        *VolatilePointer++ = 0;
        Length--;
    }

    /* Return the pointer to ensure the compiler won't optimize this away */
    return Buffer;
}

#if defined(_M_IX86)
FORCEINLINE struct _TEB * NtCurrentTeb(void)
{
    return (struct _TEB *)__readfsdword(0x18);
}
FORCEINLINE PVOID GetCurrentFiber(VOID)
{
    return (PVOID)(ULONG_PTR)__readfsdword(0x10);
}
#elif defined (_M_AMD64)
FORCEINLINE struct _TEB * NtCurrentTeb(void)
{
    return (struct _TEB *)__readgsqword(FIELD_OFFSET(NT_TIB, Self));
}
FORCEINLINE PVOID GetCurrentFiber(VOID)
{
  #ifdef NONAMELESSUNION
    return (PVOID)__readgsqword(FIELD_OFFSET(NT_TIB, DUMMYUNIONNAME.FiberData));
  #else
    return (PVOID)__readgsqword(FIELD_OFFSET(NT_TIB, FiberData));
  #endif
}
#elif defined (_M_ARM)
#define CP15_PMSELR      15, 0,  9, 12, 5
#define CP15_PMXEVCNTR   15, 0,  9, 13, 2
#define CP15_TPIDRURW    15, 0, 13,  0, 2
#define CP15_TPIDRURO    15, 0, 13,  0, 3
#define CP15_TPIDRPRW    15, 0, 13,  0, 4
FORCEINLINE struct _TEB * NtCurrentTeb(void)
{
    return (struct _TEB *)(ULONG_PTR)_MoveFromCoprocessor(CP15_TPIDRURW);
}
FORCEINLINE PVOID GetCurrentFiber(VOID)
{
  #ifdef NONAMELESSUNION
    return ((PNT_TIB )(ULONG_PTR)_MoveFromCoprocessor(CP15_TPIDRURW))->DUMMYUNIONNAME.FiberData;
  #else
    return ((PNT_TIB )(ULONG_PTR)_MoveFromCoprocessor(CP15_TPIDRURW))->FiberData;
  #endif
}
#elif defined (_M_ARM64)
FORCEINLINE struct _TEB * NtCurrentTeb(void)
{
    //UNIMPLEMENTED;
    return 0;
}
FORCEINLINE PVOID GetCurrentFiber(VOID)
{
    //UNIMPLEMENTED;
    return 0;
}
#elif defined(_M_PPC)
FORCEINLINE unsigned long _read_teb_dword(const unsigned long Offset)
{
    unsigned long result;
    __asm__("\tadd 7,13,%1\n"
            "\tlwz %0,0(7)\n"
            : "=r" (result)
            : "r" (Offset)
            : "r7");
    return result;
}
FORCEINLINE struct _TEB * NtCurrentTeb(void)
{
    return (struct _TEB *)_read_teb_dword(0x18);
}
FORCEINLINE PVOID GetCurrentFiber(void)
{
    return _read_teb_dword(0x10);
}
#else
#error Unknown architecture
#endif

FORCEINLINE PVOID GetFiberData(void)
{
    return *((PVOID *)GetCurrentFiber());
}

/* TODO: Other architectures than X86 */
#if defined(_M_IX86)
#define PF_TEMPORAL_LEVEL_1
#define PF_NON_TEMPORAL_LEVEL_ALL
#define PreFetchCacheLine(l, a)
#elif defined (_M_AMD64)
#define PreFetchCacheLine(l, a)
#elif defined(_M_PPC)
#define PreFetchCacheLine(l, a)
#elif defined(_M_ARM)
#define PreFetchCacheLine(l, a)
#elif defined(_M_ARM64)
#define PreFetchCacheLine(l, a)
#else
#error Unknown architecture
#endif

/* TODO: Other architectures than X86 */
#if defined(_M_IX86)
#if defined(_MSC_VER)
FORCEINLINE
VOID
MemoryBarrier (VOID)
{
    LONG Barrier;
    __asm { xchg Barrier, eax }
}
#else
FORCEINLINE
VOID
MemoryBarrier(VOID)
{
    LONG Barrier, *Dummy = &Barrier;
    (VOID)Dummy;
    __asm__ __volatile__("xchgl %%eax, %[Barrier]" : : [Barrier] "m" (Barrier) : "memory");
}
#endif
#elif defined (_M_AMD64)
#define MemoryBarrier __faststorefence
#elif defined(_M_PPC)
#define MemoryBarrier()
#elif defined(_M_ARM)
#define MemoryBarrier()
#elif defined(_M_ARM64)
#define MemoryBarrier()
#else
#error Unknown architecture
#endif

#if defined(_M_IX86) || defined(_M_AMD64)

#define YieldProcessor _mm_pause

__analysis_noreturn
FORCEINLINE
VOID
DbgRaiseAssertionFailure(VOID)
{
    __int2c();
}

#elif defined(_M_PPC)
#define YieldProcessor() __asm__ __volatile__("nop");
#elif defined(_M_MIPS)
#define YieldProcessor() __asm__ __volatile__("nop");
#elif defined(_M_ARM)
#define YieldProcessor __yield
#elif defined(_M_ARM64)
#define YieldProcessor __yield
#else
#error Unknown architecture
#endif

typedef struct _TP_POOL TP_POOL, *PTP_POOL;
typedef struct _TP_WORK TP_WORK, *PTP_WORK;
typedef struct _TP_CALLBACK_INSTANCE TP_CALLBACK_INSTANCE, *PTP_CALLBACK_INSTANCE;

typedef DWORD TP_VERSION, *PTP_VERSION;

typedef enum _TP_CALLBACK_PRIORITY {
  TP_CALLBACK_PRIORITY_HIGH,
  TP_CALLBACK_PRIORITY_NORMAL,
  TP_CALLBACK_PRIORITY_LOW,
  TP_CALLBACK_PRIORITY_INVALID,
  TP_CALLBACK_PRIORITY_COUNT = TP_CALLBACK_PRIORITY_INVALID
} TP_CALLBACK_PRIORITY;

typedef VOID
(NTAPI *PTP_WORK_CALLBACK)(
  _Inout_ PTP_CALLBACK_INSTANCE Instance,
  _Inout_opt_ PVOID Context,
  _Inout_ PTP_WORK Work);

typedef struct _TP_CLEANUP_GROUP TP_CLEANUP_GROUP, *PTP_CLEANUP_GROUP;

typedef VOID
(NTAPI *PTP_SIMPLE_CALLBACK)(
  _Inout_ PTP_CALLBACK_INSTANCE Instance,
  _Inout_opt_ PVOID Context);

typedef VOID
(NTAPI *PTP_CLEANUP_GROUP_CANCEL_CALLBACK)(
  _Inout_opt_ PVOID ObjectContext,
  _Inout_opt_ PVOID CleanupContext);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
typedef struct _TP_CALLBACK_ENVIRON_V3 {
  TP_VERSION Version;
  PTP_POOL Pool;
  PTP_CLEANUP_GROUP CleanupGroup;
  PTP_CLEANUP_GROUP_CANCEL_CALLBACK CleanupGroupCancelCallback;
  PVOID RaceDll;
  struct _ACTIVATION_CONTEXT *ActivationContext;
  PTP_SIMPLE_CALLBACK FinalizationCallback;
  union {
    DWORD Flags;
    struct {
      DWORD LongFunction:1;
      DWORD Persistent:1;
      DWORD Private:30;
    } s;
  } u;
  TP_CALLBACK_PRIORITY CallbackPriority;
  DWORD Size;
} TP_CALLBACK_ENVIRON_V3, TP_CALLBACK_ENVIRON, *PTP_CALLBACK_ENVIRON;
#else
typedef struct _TP_CALLBACK_ENVIRON_V1 {
  TP_VERSION Version;
  PTP_POOL Pool;
  PTP_CLEANUP_GROUP CleanupGroup;
  PTP_CLEANUP_GROUP_CANCEL_CALLBACK CleanupGroupCancelCallback;
  PVOID RaceDll;
  struct _ACTIVATION_CONTEXT *ActivationContext;
  PTP_SIMPLE_CALLBACK FinalizationCallback;
  union {
    DWORD Flags;
    struct {
      DWORD LongFunction:1;
      DWORD Persistent:1;
      DWORD Private:30;
    } s;
  } u;
} TP_CALLBACK_ENVIRON_V1, TP_CALLBACK_ENVIRON, *PTP_CALLBACK_ENVIRON;
#endif /* (_WIN32_WINNT >= _WIN32_WINNT_WIN7) */

#ifdef __WINESRC__
# define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif /* RC_INVOKED */

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* _WINNT_ */

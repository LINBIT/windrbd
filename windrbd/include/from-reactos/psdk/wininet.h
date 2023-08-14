/*
 * Copyright (C) 2000 Ulrich Czekalla
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef _WINE_WININET_H_
#define _WINE_WININET_H_

#ifdef __cplusplus
extern "C" {
#endif

#define INTERNETAPI
#define BOOLAPI _Success_(return != 0) INTERNETAPI BOOL WINAPI

typedef LPVOID HINTERNET;
typedef HINTERNET * LPHINTERNET;

typedef WORD INTERNET_PORT;
typedef INTERNET_PORT * LPINTERNET_PORT;


#define INTERNET_INVALID_PORT_NUMBER    0

#define INTERNET_DEFAULT_FTP_PORT       21
#define INTERNET_DEFAULT_GOPHER_PORT    70
#define INTERNET_DEFAULT_HTTP_PORT      80
#define INTERNET_DEFAULT_HTTPS_PORT     443
#define INTERNET_DEFAULT_SOCKS_PORT     1080

#define INTERNET_MAX_HOST_NAME_LENGTH   256
#define INTERNET_MAX_USER_NAME_LENGTH   128
#define INTERNET_MAX_PASSWORD_LENGTH    128
#define INTERNET_MAX_PORT_NUMBER_LENGTH 5
#define INTERNET_MAX_PORT_NUMBER_VALUE  65535
#define INTERNET_MAX_PATH_LENGTH        2048
#define INTERNET_MAX_SCHEME_LENGTH      32
#define INTERNET_MAX_URL_LENGTH         (INTERNET_MAX_SCHEME_LENGTH + sizeof("://")+ INTERNET_MAX_PATH_LENGTH)
#define INTERNET_KEEP_ALIVE_UNKNOWN     ((DWORD)-1)
#define INTERNET_KEEP_ALIVE_ENABLED     1
#define INTERNET_KEEP_ALIVE_DISABLED    0
#define INTERNET_REQFLAG_FROM_CACHE     0x00000001
#define INTERNET_REQFLAG_ASYNC          0x00000002
#define INTERNET_REQFLAG_VIA_PROXY      0x00000004
#define INTERNET_REQFLAG_NO_HEADERS     0x00000008
#define INTERNET_REQFLAG_PASSIVE        0x00000010
#define INTERNET_REQFLAG_CACHE_WRITE_DISABLED 0x00000040
#define INTERNET_FLAG_RELOAD            0x80000000
#define INTERNET_FLAG_RAW_DATA          0x40000000
#define INTERNET_FLAG_EXISTING_CONNECT  0x20000000
#define INTERNET_FLAG_ASYNC             0x10000000
#define INTERNET_FLAG_PASSIVE           0x08000000
#define INTERNET_FLAG_NO_CACHE_WRITE    0x04000000
#define INTERNET_FLAG_DONT_CACHE        INTERNET_FLAG_NO_CACHE_WRITE
#define INTERNET_FLAG_MAKE_PERSISTENT   0x02000000
#define INTERNET_FLAG_FROM_CACHE        0x01000000
#define INTERNET_FLAG_OFFLINE           INTERNET_FLAG_FROM_CACHE
#define INTERNET_FLAG_SECURE            0x00800000
#define INTERNET_FLAG_KEEP_CONNECTION   0x00400000
#define INTERNET_FLAG_NO_AUTO_REDIRECT  0x00200000
#define INTERNET_FLAG_READ_PREFETCH     0x00100000
#define INTERNET_FLAG_NO_COOKIES        0x00080000
#define INTERNET_FLAG_NO_AUTH           0x00040000
#define INTERNET_FLAG_CACHE_IF_NET_FAIL 0x00010000
#define INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP   0x00008000
#define INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS  0x00004000
#define INTERNET_FLAG_IGNORE_CERT_DATE_INVALID  0x00002000
#define INTERNET_FLAG_IGNORE_CERT_CN_INVALID    0x00001000
#define INTERNET_FLAG_RESYNCHRONIZE     0x00000800
#define INTERNET_FLAG_HYPERLINK         0x00000400
#define INTERNET_FLAG_NO_UI             0x00000200
#define INTERNET_FLAG_PRAGMA_NOCACHE    0x00000100
#define INTERNET_FLAG_CACHE_ASYNC       0x00000080
#define INTERNET_FLAG_FORMS_SUBMIT      0x00000040
#define INTERNET_FLAG_NEED_FILE         0x00000010
#define INTERNET_FLAG_MUST_CACHE_REQUEST INTERNET_FLAG_NEED_FILE
#define INTERNET_FLAG_TRANSFER_ASCII    FTP_TRANSFER_TYPE_ASCII
#define INTERNET_FLAG_TRANSFER_BINARY   FTP_TRANSFER_TYPE_BINARY
#define SECURITY_INTERNET_MASK  (INTERNET_FLAG_IGNORE_CERT_CN_INVALID|\
INTERNET_FLAG_IGNORE_CERT_DATE_INVALID|\
INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS|\
INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP)

#define INTERNET_FLAGS_MASK     (INTERNET_FLAG_RELOAD \
                                | INTERNET_FLAG_RAW_DATA            \
                                | INTERNET_FLAG_EXISTING_CONNECT    \
                                | INTERNET_FLAG_ASYNC               \
                                | INTERNET_FLAG_PASSIVE             \
                                | INTERNET_FLAG_NO_CACHE_WRITE      \
                                | INTERNET_FLAG_MAKE_PERSISTENT     \
                                | INTERNET_FLAG_FROM_CACHE          \
                                | INTERNET_FLAG_SECURE              \
                                | INTERNET_FLAG_KEEP_CONNECTION     \
                                | INTERNET_FLAG_NO_AUTO_REDIRECT    \
                                | INTERNET_FLAG_READ_PREFETCH       \
                                | INTERNET_FLAG_NO_COOKIES          \
                                | INTERNET_FLAG_NO_AUTH             \
                                | INTERNET_FLAG_CACHE_IF_NET_FAIL   \
                                | SECURITY_INTERNET_MASK            \
                                | INTERNET_FLAG_RESYNCHRONIZE       \
                                | INTERNET_FLAG_HYPERLINK           \
                                | INTERNET_FLAG_NO_UI               \
                                | INTERNET_FLAG_PRAGMA_NOCACHE      \
                                | INTERNET_FLAG_CACHE_ASYNC         \
                                | INTERNET_FLAG_FORMS_SUBMIT        \
                                | INTERNET_FLAG_NEED_FILE           \
                                | INTERNET_FLAG_TRANSFER_BINARY     \
                                | INTERNET_FLAG_TRANSFER_ASCII      \
                                )

#define INTERNET_ERROR_MASK_INSERT_CDROM                    0x1
#define INTERNET_ERROR_MASK_COMBINED_SEC_CERT               0x2
#define INTERNET_ERROR_MASK_NEED_MSN_SSPI_PKG               0x4
#define INTERNET_ERROR_MASK_LOGIN_FAILURE_DISPLAY_ENTITY_BODY 0x8

#define INTERNET_OPTIONS_MASK   (~INTERNET_FLAGS_MASK)
#define WININET_API_FLAG_ASYNC          0x00000001
#define WININET_API_FLAG_SYNC           0x00000004
#define WININET_API_FLAG_USE_CONTEXT    0x00000008
#define INTERNET_NO_CALLBACK            0

typedef enum {
    INTERNET_SCHEME_PARTIAL = -2,
    INTERNET_SCHEME_UNKNOWN = -1,
    INTERNET_SCHEME_DEFAULT = 0,
    INTERNET_SCHEME_FTP,   /* yes, this contradicts winhttp.h */
    INTERNET_SCHEME_GOPHER,
    INTERNET_SCHEME_HTTP,  /* yes, this contradicts winhttp.h */
    INTERNET_SCHEME_HTTPS, /* yes, this contradicts winhttp.h */
    INTERNET_SCHEME_FILE,
    INTERNET_SCHEME_NEWS,
    INTERNET_SCHEME_MAILTO,
    INTERNET_SCHEME_SOCKS, /* yes, this contradicts winhttp.h */
    INTERNET_SCHEME_JAVASCRIPT,
    INTERNET_SCHEME_VBSCRIPT,
    INTERNET_SCHEME_RES,
    INTERNET_SCHEME_FIRST = INTERNET_SCHEME_FTP,
    INTERNET_SCHEME_LAST = INTERNET_SCHEME_RES
} INTERNET_SCHEME,* LPINTERNET_SCHEME;

typedef struct {
    DWORD_PTR dwResult;
    DWORD dwError;
} INTERNET_ASYNC_RESULT,* LPINTERNET_ASYNC_RESULT;

typedef struct {
    DWORD dwAccessType;
    LPCSTR lpszProxy;
    LPCSTR lpszProxyBypass;
} INTERNET_PROXY_INFOA,* LPINTERNET_PROXY_INFOA;

typedef struct {
    DWORD dwAccessType;
    LPCWSTR lpszProxy;
    LPCWSTR lpszProxyBypass;
} INTERNET_PROXY_INFOW,* LPINTERNET_PROXY_INFOW;


DECL_WINELIB_TYPE_AW(INTERNET_PROXY_INFO)
DECL_WINELIB_TYPE_AW(LPINTERNET_PROXY_INFO)

typedef struct {
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
} INTERNET_VERSION_INFO,* LPINTERNET_VERSION_INFO;

typedef struct {
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
} HTTP_VERSION_INFO,* LPHTTP_VERSION_INFO;

typedef struct {
    DWORD dwConnectedState;
    DWORD dwFlags;
} INTERNET_CONNECTED_INFO,* LPINTERNET_CONNECTED_INFO;

#define ISO_FORCE_DISCONNECTED  0x00000001

typedef struct {
    DWORD   dwStructSize;
    LPSTR   lpszScheme;
    DWORD   dwSchemeLength;
    INTERNET_SCHEME nScheme;
    LPSTR   lpszHostName;
    DWORD   dwHostNameLength;
    INTERNET_PORT nPort;
    LPSTR   lpszUserName;
    DWORD   dwUserNameLength;
    LPSTR   lpszPassword;
    DWORD   dwPasswordLength;
    LPSTR   lpszUrlPath;
    DWORD   dwUrlPathLength;
    LPSTR   lpszExtraInfo;
    DWORD   dwExtraInfoLength;
} URL_COMPONENTSA,* LPURL_COMPONENTSA;

typedef struct {
    DWORD   dwStructSize;
    LPWSTR  lpszScheme;
    DWORD   dwSchemeLength;
    INTERNET_SCHEME nScheme;
    LPWSTR  lpszHostName;
    DWORD   dwHostNameLength;
    INTERNET_PORT nPort;
    LPWSTR  lpszUserName;
    DWORD   dwUserNameLength;
    LPWSTR  lpszPassword;
    DWORD   dwPasswordLength;
    LPWSTR  lpszUrlPath;
    DWORD   dwUrlPathLength;
    LPWSTR  lpszExtraInfo;
    DWORD   dwExtraInfoLength;
} URL_COMPONENTSW,* LPURL_COMPONENTSW;

DECL_WINELIB_TYPE_AW(URL_COMPONENTS)
DECL_WINELIB_TYPE_AW(LPURL_COMPONENTS)

typedef struct {
    FILETIME ftExpiry;
    FILETIME ftStart;
    LPSTR lpszSubjectInfo;
    LPSTR lpszIssuerInfo;
    LPSTR lpszProtocolName;
    LPSTR lpszSignatureAlgName;
    LPSTR lpszEncryptionAlgName;
    DWORD dwKeySize;

} INTERNET_CERTIFICATE_INFOA,* LPINTERNET_CERTIFICATE_INFOA;

typedef struct {
    FILETIME ftExpiry;
    FILETIME ftStart;
    LPWSTR lpszSubjectInfo;
    LPWSTR lpszIssuerInfo;
    LPWSTR lpszProtocolName;
    LPWSTR lpszSignatureAlgName;
    LPWSTR lpszEncryptionAlgName;
    DWORD dwKeySize;

} INTERNET_CERTIFICATE_INFOW,* LPINTERNET_CERTIFICATE_INFOW;

DECL_WINELIB_TYPE_AW(INTERNET_CERTIFICATE_INFO)
DECL_WINELIB_TYPE_AW(LPINTERNET_CERTIFICATE_INFO)

typedef struct _INTERNET_BUFFERSA {
    DWORD dwStructSize;
    struct _INTERNET_BUFFERSA * Next;
    LPCSTR   lpcszHeader;
    DWORD dwHeadersLength;
    DWORD dwHeadersTotal;
    LPVOID lpvBuffer;
    DWORD dwBufferLength;
    DWORD dwBufferTotal;
    DWORD dwOffsetLow;
    DWORD dwOffsetHigh;
} INTERNET_BUFFERSA,* LPINTERNET_BUFFERSA;

typedef struct _INTERNET_BUFFERSW {
    DWORD dwStructSize;
    struct _INTERNET_BUFFERSW * Next;
    LPCWSTR  lpcszHeader;
    DWORD dwHeadersLength;
    DWORD dwHeadersTotal;
    LPVOID lpvBuffer;
    DWORD dwBufferLength;
    DWORD dwBufferTotal;
    DWORD dwOffsetLow;
    DWORD dwOffsetHigh;
} INTERNET_BUFFERSW,* LPINTERNET_BUFFERSW;

DECL_WINELIB_TYPE_AW(INTERNET_BUFFERS)
DECL_WINELIB_TYPE_AW(LPINTERNET_BUFFERS)

#define GROUP_OWNER_STORAGE_SIZE 4
#define GROUPNAME_MAX_LENGTH 120

typedef struct _INTERNET_CACHE_GROUP_INFOA {
    DWORD dwGroupSize;
    DWORD dwGroupFlags;
    DWORD dwGroupType;
    DWORD dwDiskUsage;
    DWORD dwDiskQuota;
    DWORD dwOwnerStorage[GROUP_OWNER_STORAGE_SIZE];
    CHAR  szGroupName[GROUPNAME_MAX_LENGTH];
} INTERNET_CACHE_GROUP_INFOA, * LPINTERNET_CACHE_GROUP_INFOA;

typedef struct _INTERNET_CACHE_GROUP_INFOW {
    DWORD dwGroupSize;
    DWORD dwGroupFlags;
    DWORD dwGroupType;
    DWORD dwDiskUsage;
    DWORD dwDiskQuota;
    DWORD dwOwnerStorage[GROUP_OWNER_STORAGE_SIZE];
    WCHAR szGroupName[GROUPNAME_MAX_LENGTH];
} INTERNET_CACHE_GROUP_INFOW, *LPINTERNET_CACHE_GROUP_INFOW;

DECL_WINELIB_TYPE_AW(INTERNET_CACHE_GROUP_INFO)
DECL_WINELIB_TYPE_AW(LPINTERNET_CACHE_GROUP_INFO)

typedef struct _INTERNET_PER_CONN_OPTIONA {
    DWORD dwOption;
    union {
        DWORD    dwValue;
        LPSTR    pszValue;
        FILETIME ftValue;
    } Value;
} INTERNET_PER_CONN_OPTIONA, *LPINTERNET_PER_CONN_OPTIONA;

typedef struct _INTERNET_PER_CONN_OPTIONW {
    DWORD dwOption;
    union {
        DWORD    dwValue;
        LPWSTR   pszValue;
        FILETIME ftValue;
    } Value;
} INTERNET_PER_CONN_OPTIONW, *LPINTERNET_PER_CONN_OPTIONW;

DECL_WINELIB_TYPE_AW(INTERNET_PER_CONN_OPTION)
DECL_WINELIB_TYPE_AW(LPINTERNET_PER_CONN_OPTION)

#define INTERNET_PER_CONN_FLAGS                        1
#define INTERNET_PER_CONN_PROXY_SERVER                 2
#define INTERNET_PER_CONN_PROXY_BYPASS                 3
#define INTERNET_PER_CONN_AUTOCONFIG_URL               4
#define INTERNET_PER_CONN_AUTODISCOVERY_FLAGS          5
#define INTERNET_PER_CONN_AUTOCONFIG_SECONDARY_URL     6
#define INTERNET_PER_CONN_AUTOCONFIG_RELOAD_DELAY_MINS 7
#define INTERNET_PER_CONN_AUTOCONFIG_LAST_DETECT_TIME  8
#define INTERNET_PER_CONN_AUTOCONFIG_LAST_DETECT_URL   9
#define INTERNET_PER_CONN_FLAGS_UI                     10

/* Values for INTERNET_PER_CONN_FLAGS */
#define PROXY_TYPE_DIRECT         0x00000001
#define PROXY_TYPE_PROXY          0x00000002
#define PROXY_TYPE_AUTO_PROXY_URL 0x00000004
#define PROXY_TYPE_AUTO_DETECT    0x00000008
/* Values for INTERNET_PER_CONN_AUTODISCOVERY_FLAGS */
#define AUTO_PROXY_FLAG_USER_SET                0x00000001
#define AUTO_PROXY_FLAG_ALWAYS_DETECT           0x00000002
#define AUTO_PROXY_FLAG_DETECTION_RUN           0x00000004
#define AUTO_PROXY_FLAG_MIGRATED                0x00000008
#define AUTO_PROXY_FLAG_DONT_CACHE_PROXY_RESULT 0x00000010
#define AUTO_PROXY_FLAG_CACHE_INIT_RUN          0x00000020
#define AUTO_PROXY_FLAG_DETECTION_SUSPECT       0x00000040

typedef struct _INTERNET_PER_CONN_OPTION_LISTA {
    DWORD                       dwSize;
    LPSTR                       pszConnection;
    DWORD                       dwOptionCount;
    DWORD                       dwOptionError;
    LPINTERNET_PER_CONN_OPTIONA pOptions;
} INTERNET_PER_CONN_OPTION_LISTA, *LPINTERNET_PER_CONN_OPTION_LISTA;

typedef struct _INTERNET_PER_CONN_OPTION_LISTW {
    DWORD                       dwSize;
    LPWSTR                      pszConnection;
    DWORD                       dwOptionCount;
    DWORD                       dwOptionError;
    LPINTERNET_PER_CONN_OPTIONW pOptions;
} INTERNET_PER_CONN_OPTION_LISTW, *LPINTERNET_PER_CONN_OPTION_LISTW;

DECL_WINELIB_TYPE_AW(INTERNET_PER_CONN_OPTION_LIST)
DECL_WINELIB_TYPE_AW(LPINTERNET_PER_CONN_OPTION_LIST)

typedef struct _INTERNET_DIAGNOSTIC_SOCKET_INFO
{
    DWORD_PTR Socket;
    DWORD     SourcePort;
    DWORD     DestPort;
    DWORD     Flags;
} INTERNET_DIAGNOSTIC_SOCKET_INFO, *LPINTERNET_DIAGNOSTIC_SOCKET_INFO;

#define IDSI_FLAG_KEEP_ALIVE 0x00000001
#define IDSI_FLAG_SECURE     0x00000002
#define IDSI_FLAG_PROXY      0x00000004
#define IDSI_FLAG_TUNNEL     0x00000008

BOOLAPI
InternetTimeFromSystemTimeA(
  _In_ CONST SYSTEMTIME *pst,
  _In_ DWORD dwRFC,
  _Out_writes_bytes_(cbTime) LPSTR lpszTime,
  _In_ DWORD cbTime);

BOOLAPI
InternetTimeFromSystemTimeW(
  _In_ CONST SYSTEMTIME *pst,
  _In_ DWORD dwRFC,
  _Out_writes_bytes_(cbTime) LPWSTR lpszTime,
  _In_ DWORD cbTime);

#define InternetTimeFromSystemTime WINELIB_NAME_AW(InternetTimeFromSystemTime)

#define INTERNET_RFC1123_FORMAT    0
#define INTERNET_RFC1123_BUFSIZE   30

BOOLAPI
InternetTimeToSystemTimeA(
  _In_ LPCSTR,
  _Out_ SYSTEMTIME *,
  _Reserved_ DWORD);

BOOLAPI
InternetTimeToSystemTimeW(
  _In_ LPCWSTR,
  _Out_ SYSTEMTIME *,
  _Reserved_ DWORD);

#define InternetTimeToSystemTime WINELIB_NAME_AW(InternetTimeToSystemTime)

BOOLAPI
InternetCrackUrlA(
  _In_reads_(dwUrlLength) LPCSTR lpszUrl,
  _In_ DWORD dwUrlLength,
  _In_ DWORD dwFlags,
  _Inout_ LPURL_COMPONENTSA lpUrlComponents);

BOOLAPI
InternetCrackUrlW(
  _In_reads_(dwUrlLength) LPCWSTR lpszUrl,
  _In_ DWORD dwUrlLength,
  _In_ DWORD dwFlags,
  _Inout_ LPURL_COMPONENTSW lpUrlComponents);

#define InternetCrackUrl WINELIB_NAME_AW(InternetCrackUrl)

BOOLAPI
InternetCreateUrlA(
  _In_ LPURL_COMPONENTSA lpUrlComponents,
  _In_ DWORD dwFlags,
  _Out_writes_opt_(*lpdwUrlLength) LPSTR lpszUrl,
  _Inout_ LPDWORD lpdwUrlLength);

BOOLAPI
InternetCreateUrlW(
  _In_ LPURL_COMPONENTSW lpUrlComponents,
  _In_ DWORD dwFlags,
  _Out_writes_opt_(*lpdwUrlLength) LPWSTR lpszUrl,
  _Inout_ LPDWORD lpdwUrlLength);

#define InternetCreateUrl WINELIB_NAME_AW(InternetCreateUrl)

BOOLAPI
InternetCanonicalizeUrlA(
  _In_ LPCSTR lpszUrl,
  _Out_writes_(*lpdwBufferLength) LPSTR lpszBuffer,
  _Inout_ LPDWORD lpdwBufferLength,
  _In_ DWORD dwFlags);

BOOLAPI
InternetCanonicalizeUrlW(
  _In_ LPCWSTR lpszUrl,
  _Out_writes_(*lpdwBufferLength) LPWSTR lpszBuffer,
  _Inout_ LPDWORD lpdwBufferLength,
  _In_ DWORD dwFlags);

#define InternetCanonicalizeUrl WINELIB_NAME_AW(InternetCanonicalizeUrl)

BOOLAPI
InternetCombineUrlA(
  _In_ LPCSTR lpszBaseUrl,
  _In_ LPCSTR lpszRelativeUrl,
  _Out_writes_(*lpdwBufferLength) LPSTR lpszBuffer,
  _Inout_ LPDWORD lpdwBufferLength,
  _In_ DWORD dwFlags);

BOOLAPI
InternetCombineUrlW(
  _In_ LPCWSTR lpszBaseUrl,
  _In_ LPCWSTR lpszRelativeUrl,
  _Out_writes_(*lpdwBufferLength) LPWSTR lpszBuffer,
  _Inout_ LPDWORD lpdwBufferLength,
  _In_ DWORD dwFlags);

#define InternetCombineUrl WINELIB_NAME_AW(InternetCombineUrl)

#define ICU_ESCAPE      0x80000000
#define ICU_USERNAME    0x40000000
#define ICU_NO_ENCODE   0x20000000
#define ICU_DECODE      0x10000000
#define ICU_NO_META     0x08000000
#define ICU_ENCODE_SPACES_ONLY 0x04000000
#define ICU_BROWSER_MODE 0x02000000
#define ICU_ENCODE_PERCENT 0x00001000

INTERNETAPI
HINTERNET
WINAPI
InternetOpenA(
  _In_opt_ LPCSTR,
  _In_ DWORD,
  _In_opt_ LPCSTR,
  _In_opt_ LPCSTR,
  _In_ DWORD);

INTERNETAPI
HINTERNET
WINAPI
InternetOpenW(
  _In_opt_ LPCWSTR,
  _In_ DWORD,
  _In_opt_ LPCWSTR,
  _In_opt_ LPCWSTR,
  _In_ DWORD);

#define InternetOpen WINELIB_NAME_AW(InternetOpen)

#define INTERNET_OPEN_TYPE_PRECONFIG                    0
#define INTERNET_OPEN_TYPE_DIRECT                       1
#define INTERNET_OPEN_TYPE_PROXY                        3
#define INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY  4
#define PRE_CONFIG_INTERNET_ACCESS  INTERNET_OPEN_TYPE_PRECONFIG
#define LOCAL_INTERNET_ACCESS       INTERNET_OPEN_TYPE_DIRECT
#define CERN_PROXY_INTERNET_ACCESS  INTERNET_OPEN_TYPE_PROXY

BOOLAPI InternetCloseHandle(_In_ HINTERNET);

INTERNETAPI
HINTERNET
WINAPI
InternetConnectA(
  _In_ HINTERNET,
  _In_ LPCSTR,
  _In_ INTERNET_PORT,
  _In_opt_ LPCSTR,
  _In_opt_ LPCSTR,
  _In_ DWORD,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

INTERNETAPI
HINTERNET
WINAPI
InternetConnectW(
  _In_ HINTERNET,
  _In_ LPCWSTR,
  _In_ INTERNET_PORT,
  _In_opt_ LPCWSTR,
  _In_opt_ LPCWSTR,
  _In_ DWORD,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

#define InternetConnect WINELIB_NAME_AW(InternetConnect)

#define INTERNET_SERVICE_URL    0
#define INTERNET_SERVICE_FTP    1
#define INTERNET_SERVICE_GOPHER 2
#define INTERNET_SERVICE_HTTP   3

#define InternetConnectUrl(hInternet,lpszUrl,dwFlags,dwContext) \
    InternetConnect(hInternet,\
                    lpszUrl,\
                    INTERNET_INVALID_PORT_NUMBER,\
                    NULL,\
                    NULL,\
                    INTERNET_SERVICE_URL,\
                    dwFlags,\
                    dwContext                       \
                    )

INTERNETAPI
HINTERNET
WINAPI
InternetOpenUrlA(
  _In_ HINTERNET hInternet,
  _In_ LPCSTR lpszUrl,
  _In_reads_opt_(dwHeadersLength) LPCSTR lpszHeaders,
  _In_ DWORD dwHeadersLength,
  _In_ DWORD dwFlags,
  _In_opt_ DWORD_PTR dwContext);

INTERNETAPI
HINTERNET
WINAPI
InternetOpenUrlW(
  _In_ HINTERNET hInternet,
  _In_ LPCWSTR lpszUrl,
  _In_reads_opt_(dwHeadersLength) LPCWSTR lpszHeaders,
  _In_ DWORD dwHeadersLength,
  _In_ DWORD dwFlags,
  _In_opt_ DWORD_PTR dwContext);

#define InternetOpenUrl WINELIB_NAME_AW(InternetOpenUrl)

BOOLAPI
InternetReadFile(
  _In_ HINTERNET hFile,
  _Out_writes_bytes_(dwNumberOfBytesToRead) __out_data_source(NETWORK) LPVOID lpBuffer,
  _In_ DWORD dwNumberOfBytesToRead,
  _Out_ LPDWORD lpdwNumberOfBytesRead);

BOOLAPI
InternetReadFileExA(
  _In_ HINTERNET hFile,
  _Out_ __out_data_source(NETWORK) LPINTERNET_BUFFERSA lpBuffersOut,
  _In_ DWORD dwFlags,
  _In_opt_ DWORD_PTR dwContext);

BOOLAPI
InternetReadFileExW(
  _In_ HINTERNET hFile,
  _Out_ __out_data_source(NETWORK) LPINTERNET_BUFFERSW lpBuffersOut,
  _In_ DWORD dwFlags,
  _In_opt_ DWORD_PTR dwContext);

#define InternetReadFileEx WINELIB_NAME_AW(InternetReadFileEx)

#define IRF_ASYNC       WININET_API_FLAG_ASYNC
#define IRF_SYNC        WININET_API_FLAG_SYNC
#define IRF_USE_CONTEXT WININET_API_FLAG_USE_CONTEXT
#define IRF_NO_WAIT     0x00000008

INTERNETAPI
DWORD
WINAPI
InternetSetFilePointer(
  _In_ HINTERNET,
  _In_ LONG,
  _Inout_opt_ PVOID,
  _In_ DWORD,
  _Reserved_ DWORD_PTR);

BOOLAPI
InternetWriteFile(
  _In_ HINTERNET hFile,
  _In_reads_bytes_(dwNumberOfBytesToWrite) LPCVOID lpBuffer,
  _In_ DWORD dwNumberOfBytesToWrite,
  _Out_ LPDWORD lpdwNumberOfBytesWritten);

BOOLAPI
InternetQueryDataAvailable(
  _In_ HINTERNET hFile,
  _Out_opt_ __out_data_source(NETWORK) LPDWORD lpdwNumberOfBytesAvailable,
  _In_ DWORD dwFlags,
  _In_opt_ DWORD_PTR dwContext);

BOOLAPI InternetFindNextFileA(_In_ HINTERNET, _Out_ LPVOID);
BOOLAPI InternetFindNextFileW(_In_ HINTERNET, _Out_ LPVOID);
#define InternetFindNextFile  WINELIB_NAME_AW(InternetFindNextFile)

BOOLAPI
InternetQueryOptionA(
  _In_opt_ HINTERNET hInternet,
  _In_ DWORD dwOption,
  _Out_writes_bytes_to_opt_(*lpdwBufferLength, *lpdwBufferLength) __out_data_source(NETWORK) LPVOID lpBuffer,
  _Inout_ LPDWORD lpdwBufferLength);

BOOLAPI
InternetQueryOptionW(
  _In_opt_ HINTERNET hInternet,
  _In_ DWORD dwOption,
  _Out_writes_bytes_to_opt_(*lpdwBufferLength, *lpdwBufferLength) __out_data_source(NETWORK) LPVOID lpBuffer,
  _Inout_ LPDWORD lpdwBufferLength);

#define InternetQueryOption WINELIB_NAME_AW(InternetQueryOption)

BOOLAPI InternetSetOptionA(_In_opt_ HINTERNET, _In_ DWORD, _In_opt_ LPVOID, _In_ DWORD);
BOOLAPI InternetSetOptionW(_In_opt_ HINTERNET, _In_ DWORD, _In_opt_ LPVOID, _In_ DWORD);
#define InternetSetOption  WINELIB_NAME_AW(InternetSetOption)

BOOLAPI
InternetSetOptionExA(
  _In_opt_ HINTERNET,
  _In_ DWORD,
  _In_opt_ LPVOID,
  _In_ DWORD,
  _In_ DWORD);

BOOLAPI
InternetSetOptionExW(
  _In_opt_ HINTERNET,
  _In_ DWORD,
  _In_opt_ LPVOID,
  _In_ DWORD,
  _In_ DWORD);

#define InternetSetOptionEx WINELIB_NAME_AW(InternetSetOptionEx)

BOOLAPI InternetLockRequestFile(_In_ HINTERNET, _Out_ HANDLE *);
BOOLAPI InternetUnlockRequestFile(_Inout_ HANDLE);

#define ISO_GLOBAL      0x00000001
#define ISO_REGISTRY    0x00000002

#define ISO_VALID_FLAGS (ISO_GLOBAL | ISO_REGISTRY)
#define INTERNET_OPTION_CALLBACK                1
#define INTERNET_OPTION_CONNECT_TIMEOUT         2
#define INTERNET_OPTION_CONNECT_RETRIES         3
#define INTERNET_OPTION_CONNECT_BACKOFF         4
#define INTERNET_OPTION_SEND_TIMEOUT            5
#define INTERNET_OPTION_CONTROL_SEND_TIMEOUT    INTERNET_OPTION_SEND_TIMEOUT
#define INTERNET_OPTION_RECEIVE_TIMEOUT         6
#define INTERNET_OPTION_CONTROL_RECEIVE_TIMEOUT INTERNET_OPTION_RECEIVE_TIMEOUT
#define INTERNET_OPTION_DATA_SEND_TIMEOUT       7
#define INTERNET_OPTION_DATA_RECEIVE_TIMEOUT    8
#define INTERNET_OPTION_HANDLE_TYPE             9
#define INTERNET_OPTION_LISTEN_TIMEOUT          11
#define INTERNET_OPTION_READ_BUFFER_SIZE        12
#define INTERNET_OPTION_WRITE_BUFFER_SIZE       13
#define INTERNET_OPTION_ASYNC_ID                15
#define INTERNET_OPTION_ASYNC_PRIORITY          16
#define INTERNET_OPTION_PARENT_HANDLE           21
#define INTERNET_OPTION_KEEP_CONNECTION         22
#define INTERNET_OPTION_REQUEST_FLAGS           23
#define INTERNET_OPTION_EXTENDED_ERROR          24
#define INTERNET_OPTION_OFFLINE_MODE            26
#define INTERNET_OPTION_CACHE_STREAM_HANDLE     27
#define INTERNET_OPTION_USERNAME                28
#define INTERNET_OPTION_PASSWORD                29
#define INTERNET_OPTION_ASYNC                   30
#define INTERNET_OPTION_SECURITY_FLAGS          31
#define INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT 32
#define INTERNET_OPTION_DATAFILE_NAME           33
#define INTERNET_OPTION_URL                     34
#define INTERNET_OPTION_SECURITY_CERTIFICATE    35
#define INTERNET_OPTION_SECURITY_KEY_BITNESS    36
#define INTERNET_OPTION_REFRESH                 37
#define INTERNET_OPTION_PROXY                   38
#define INTERNET_OPTION_SETTINGS_CHANGED        39
#define INTERNET_OPTION_VERSION                 40
#define INTERNET_OPTION_USER_AGENT              41
#define INTERNET_OPTION_END_BROWSER_SESSION     42
#define INTERNET_OPTION_PROXY_USERNAME          43
#define INTERNET_OPTION_PROXY_PASSWORD          44
#define INTERNET_OPTION_CONTEXT_VALUE           45
#define INTERNET_OPTION_CONNECT_LIMIT           46
#define INTERNET_OPTION_SECURITY_SELECT_CLIENT_CERT 47
#define INTERNET_OPTION_POLICY                  48
#define INTERNET_OPTION_DISCONNECTED_TIMEOUT    49
#define INTERNET_OPTION_CONNECTED_STATE         50
#define INTERNET_OPTION_IDLE_STATE              51
#define INTERNET_OPTION_OFFLINE_SEMANTICS       52
#define INTERNET_OPTION_SECONDARY_CACHE_KEY     53
#define INTERNET_OPTION_CALLBACK_FILTER         54
#define INTERNET_OPTION_CONNECT_TIME            55
#define INTERNET_OPTION_SEND_THROUGHPUT         56
#define INTERNET_OPTION_RECEIVE_THROUGHPUT      57
#define INTERNET_OPTION_REQUEST_PRIORITY        58
#define INTERNET_OPTION_HTTP_VERSION            59
#define INTERNET_OPTION_RESET_URLCACHE_SESSION  60
#define INTERNET_OPTION_ERROR_MASK              62
#define INTERNET_OPTION_FROM_CACHE_TIMEOUT      63
#define INTERNET_OPTION_BYPASS_EDITED_ENTRY     64
#define INTERNET_OPTION_HTTP_DECODING           65
#define INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO  67
#define INTERNET_OPTION_CODEPAGE                68
#define INTERNET_OPTION_CACHE_TIMESTAMPS        69
#define INTERNET_OPTION_DISABLE_AUTODIAL        70
#define INTERNET_OPTION_MAX_CONNS_PER_SERVER    73
#define INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER 74
#define INTERNET_OPTION_PER_CONNECTION_OPTION   75
#define INTERNET_OPTION_DIGEST_AUTH_UNLOAD      76
#define INTERNET_OPTION_IGNORE_OFFLINE          77
#define INTERNET_OPTION_IDENTITY                78
#define INTERNET_OPTION_REMOVE_IDENTITY         79
#define INTERNET_OPTION_ALTER_IDENTITY          80
#define INTERNET_OPTION_SUPPRESS_BEHAVIOR       81
#define INTERNET_OPTION_AUTODIAL_MODE           82
#define INTERNET_OPTION_AUTODIAL_CONNECTION     83
#define INTERNET_OPTION_CLIENT_CERT_CONTEXT     84
#define INTERNET_OPTION_AUTH_FLAGS              85
#define INTERNET_OPTION_COOKIES_3RD_PARTY       86
#define INTERNET_OPTION_DISABLE_PASSPORT_AUTH   87
#define INTERNET_OPTION_SEND_UTF8_SERVERNAME_TO_PROXY 88
#define INTERNET_OPTION_EXEMPT_CONNECTION_LIMIT 89
#define INTERNET_OPTION_ENABLE_PASSPORT_AUTH    90

#define INTERNET_OPTION_HIBERNATE_INACTIVE_WORKER_THREADS 91
#define INTERNET_OPTION_ACTIVATE_WORKER_THREADS           92
#define INTERNET_OPTION_RESTORE_WORKER_THREAD_DEFAULTS    93
#define INTERNET_OPTION_SOCKET_SEND_BUFFER_LENGTH         94

#define INTERNET_OPTION_PROXY_SETTINGS_CHANGED  95
#define INTERNET_OPTION_DATAFILE_EXT            96

#define INTERNET_OPTION_CODEPAGE_PATH           100
#define INTERNET_OPTION_CODEPAGE_EXTRA          101
#define INTERNET_OPTION_IDN                     102
#define INTERNET_OPTION_MAX_CONNS_PER_PROXY     103
#define INTERNET_OPTION_SUPPRESS_SERVER_AUTH    104
#define INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT 105


#define INTERNET_FIRST_OPTION                   INTERNET_OPTION_CALLBACK
#define INTERNET_LAST_OPTION                    INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT

#define INTERNET_PRIORITY_FOREGROUND            1000
#define INTERNET_HANDLE_TYPE_INTERNET           1
#define INTERNET_HANDLE_TYPE_CONNECT_FTP        2
#define INTERNET_HANDLE_TYPE_CONNECT_GOPHER     3
#define INTERNET_HANDLE_TYPE_CONNECT_HTTP       4
#define INTERNET_HANDLE_TYPE_FTP_FIND           5
#define INTERNET_HANDLE_TYPE_FTP_FIND_HTML      6
#define INTERNET_HANDLE_TYPE_FTP_FILE           7
#define INTERNET_HANDLE_TYPE_FTP_FILE_HTML      8
#define INTERNET_HANDLE_TYPE_GOPHER_FIND        9
#define INTERNET_HANDLE_TYPE_GOPHER_FIND_HTML   10
#define INTERNET_HANDLE_TYPE_GOPHER_FILE        11
#define INTERNET_HANDLE_TYPE_GOPHER_FILE_HTML   12
#define INTERNET_HANDLE_TYPE_HTTP_REQUEST       13
#define SECURITY_FLAG_SECURE                    0x00000001
#define SECURITY_FLAG_STRENGTH_WEAK             0x10000000
#define SECURITY_FLAG_STRENGTH_MEDIUM           0x40000000
#define SECURITY_FLAG_STRENGTH_STRONG           0x20000000
#define SECURITY_FLAG_UNKNOWNBIT                0x80000000
#define SECURITY_FLAG_NORMALBITNESS             SECURITY_FLAG_STRENGTH_WEAK
#define SECURITY_FLAG_SSL                       0x00000002
#define SECURITY_FLAG_SSL3                      0x00000004
#define SECURITY_FLAG_PCT                       0x00000008
#define SECURITY_FLAG_PCT4                      0x00000010
#define SECURITY_FLAG_IETFSSL4                  0x00000020
#define SECURITY_FLAG_40BIT                     SECURITY_FLAG_STRENGTH_WEAK
#define SECURITY_FLAG_128BIT                    SECURITY_FLAG_STRENGTH_STRONG
#define SECURITY_FLAG_56BIT                     SECURITY_FLAG_STRENGTH_MEDIUM
#define SECURITY_FLAG_IGNORE_REVOCATION         0x00000080
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA         0x00000100
#define SECURITY_FLAG_IGNORE_WRONG_USAGE        0x00000200
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID    INTERNET_FLAG_IGNORE_CERT_CN_INVALID
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID  INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
#define SECURITY_FLAG_IGNORE_REDIRECT_TO_HTTPS  INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS
#define SECURITY_FLAG_IGNORE_REDIRECT_TO_HTTP   INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP
#define SECURITY_SET_MASK       (SECURITY_FLAG_IGNORE_REVOCATION |\
                                 SECURITY_FLAG_IGNORE_UNKNOWN_CA |\
                                 SECURITY_FLAG_IGNORE_CERT_CN_INVALID |\
                                 SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |\
                                 SECURITY_FLAG_IGNORE_WRONG_USAGE)



BOOLAPI
InternetGetLastResponseInfoA(
  _Out_ LPDWORD lpdwError,
  _Out_writes_opt_(*lpdwBufferLength) LPSTR lpszBuffer,
  _Inout_ LPDWORD lpdwBufferLength);

BOOLAPI
InternetGetLastResponseInfoW(
  _Out_ LPDWORD lpdwError,
  _Out_writes_opt_(*lpdwBufferLength) LPWSTR lpszBuffer,
  _Inout_ LPDWORD lpdwBufferLength);

#define InternetGetLastResponseInfo WINELIB_NAME_AW(InternetGetLastResponseInfo)

typedef VOID
(CALLBACK *INTERNET_STATUS_CALLBACK)(
  _In_ HINTERNET,
  _In_opt_ DWORD_PTR,
  _In_ DWORD,
  _In_opt_ LPVOID,
  _In_ DWORD);
typedef INTERNET_STATUS_CALLBACK * LPINTERNET_STATUS_CALLBACK;

INTERNETAPI
INTERNET_STATUS_CALLBACK
WINAPI
InternetSetStatusCallbackA(
  _In_ HINTERNET,
  _In_opt_ INTERNET_STATUS_CALLBACK);

INTERNETAPI
INTERNET_STATUS_CALLBACK
WINAPI
InternetSetStatusCallbackW(
  _In_ HINTERNET,
  _In_opt_ INTERNET_STATUS_CALLBACK);

#define InternetSetStatusCallback WINELIB_NAME_AW(InternetSetStatusCallback)

#define INTERNET_STATUS_RESOLVING_NAME          10
#define INTERNET_STATUS_NAME_RESOLVED           11
#define INTERNET_STATUS_CONNECTING_TO_SERVER    20
#define INTERNET_STATUS_CONNECTED_TO_SERVER     21
#define INTERNET_STATUS_SENDING_REQUEST         30
#define INTERNET_STATUS_REQUEST_SENT            31
#define INTERNET_STATUS_RECEIVING_RESPONSE      40
#define INTERNET_STATUS_RESPONSE_RECEIVED       41
#define INTERNET_STATUS_CTL_RESPONSE_RECEIVED   42
#define INTERNET_STATUS_PREFETCH                43
#define INTERNET_STATUS_CLOSING_CONNECTION      50
#define INTERNET_STATUS_CONNECTION_CLOSED       51
#define INTERNET_STATUS_HANDLE_CREATED          60
#define INTERNET_STATUS_HANDLE_CLOSING          70
#define INTERNET_STATUS_DETECTING_PROXY         80
#define INTERNET_STATUS_REQUEST_COMPLETE        100
#define INTERNET_STATUS_REDIRECT                110
#define INTERNET_STATUS_INTERMEDIATE_RESPONSE   120
#define INTERNET_STATUS_USER_INPUT_REQUIRED     140
#define INTERNET_STATUS_STATE_CHANGE            200
#define INTERNET_STATUS_COOKIE_SENT             320
#define INTERNET_STATUS_COOKIE_RECEIVED         321
#define INTERNET_STATUS_PRIVACY_IMPACTED        324
#define INTERNET_STATUS_P3P_HEADER              325
#define INTERNET_STATUS_P3P_POLICYREF           326
#define INTERNET_STATUS_COOKIE_HISTORY          327
#define INTERNET_STATE_CONNECTED                0x00000001
#define INTERNET_STATE_DISCONNECTED             0x00000002
#define INTERNET_STATE_DISCONNECTED_BY_USER     0x00000010
#define INTERNET_STATE_IDLE                     0x00000100
#define INTERNET_STATE_BUSY                     0x00000200

#define INTERNET_INVALID_STATUS_CALLBACK        ((INTERNET_STATUS_CALLBACK)(-1))

#define FTP_TRANSFER_TYPE_UNKNOWN   0x00000000
#define FTP_TRANSFER_TYPE_ASCII     0x00000001
#define FTP_TRANSFER_TYPE_BINARY    0x00000002
#define FTP_TRANSFER_TYPE_MASK      (FTP_TRANSFER_TYPE_ASCII | FTP_TRANSFER_TYPE_BINARY)

BOOLAPI
FtpCommandA(
  _In_ HINTERNET,
  _In_ BOOL,
  _In_ DWORD,
  _In_ LPCSTR,
  _In_opt_ DWORD_PTR,
  _Out_opt_ HINTERNET *);

BOOLAPI
FtpCommandW(
  _In_ HINTERNET,
  _In_ BOOL,
  _In_ DWORD,
  _In_ LPCWSTR,
  _In_opt_ DWORD_PTR,
  _Out_opt_ HINTERNET *);

#define FtpCommand WINELIB_NAME_AW(FtpCommand)

INTERNETAPI
HINTERNET
WINAPI
FtpFindFirstFileA(
  _In_ HINTERNET,
  _In_opt_ LPCSTR,
  _Out_opt_ LPWIN32_FIND_DATAA,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

INTERNETAPI
HINTERNET
WINAPI
FtpFindFirstFileW(
  _In_ HINTERNET,
  _In_opt_ LPCWSTR,
  _Out_opt_ LPWIN32_FIND_DATAW,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

#define FtpFindFirstFile WINELIB_NAME_AW(FtpFindFirstFile)

BOOLAPI
FtpGetFileA(
  _In_ HINTERNET,
  _In_ LPCSTR,
  _In_ LPCSTR,
  _In_ BOOL,
  _In_ DWORD,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

BOOLAPI
FtpGetFileW(
  _In_ HINTERNET,
  _In_ LPCWSTR,
  _In_ LPCWSTR,
  _In_ BOOL,
  _In_ DWORD,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

#define FtpGetFile WINELIB_NAME_AW(FtpGetFile)

DWORD WINAPI FtpGetFileSize(_In_ HINTERNET, _Out_opt_ LPDWORD);

BOOLAPI
FtpPutFileA(
  _In_ HINTERNET,
  _In_ LPCSTR,
  _In_ LPCSTR,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

BOOLAPI
FtpPutFileW(
  _In_ HINTERNET,
  _In_ LPCWSTR,
  _In_ LPCWSTR,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

#define FtpPutFile WINELIB_NAME_AW(FtpPutFile)

BOOLAPI FtpDeleteFileA(_In_ HINTERNET, _In_ LPCSTR);
BOOLAPI FtpDeleteFileW(_In_ HINTERNET, _In_ LPCWSTR);
#define FtpDeleteFile  WINELIB_NAME_AW(FtpDeleteFile)

BOOLAPI FtpRenameFileA(_In_ HINTERNET, _In_ LPCSTR, _In_ LPCSTR);
BOOLAPI FtpRenameFileW(_In_ HINTERNET, _In_ LPCWSTR, _In_ LPCWSTR);
#define FtpRenameFile  WINELIB_NAME_AW(FtpRenameFile)

INTERNETAPI
HINTERNET
WINAPI
FtpOpenFileA(
  _In_ HINTERNET,
  _In_ LPCSTR,
  _In_ DWORD,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

INTERNETAPI
HINTERNET
WINAPI
FtpOpenFileW(
  _In_ HINTERNET,
  _In_ LPCWSTR,
  _In_ DWORD,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

#define FtpOpenFile WINELIB_NAME_AW(FtpOpenFile)

BOOLAPI FtpCreateDirectoryA(_In_ HINTERNET, _In_ LPCSTR);
BOOLAPI FtpCreateDirectoryW(_In_ HINTERNET, _In_ LPCWSTR);
#define FtpCreateDirectory  WINELIB_NAME_AW(FtpCreateDirectory)

BOOLAPI FtpRemoveDirectoryA(_In_ HINTERNET, _In_ LPCSTR);
BOOLAPI FtpRemoveDirectoryW(_In_ HINTERNET, _In_ LPCWSTR);
#define FtpRemoveDirectory  WINELIB_NAME_AW(FtpRemoveDirectory)

BOOLAPI FtpSetCurrentDirectoryA(_In_ HINTERNET, _In_ LPCSTR);
BOOLAPI FtpSetCurrentDirectoryW(_In_ HINTERNET, _In_ LPCWSTR);
#define FtpSetCurrentDirectory  WINELIB_NAME_AW(FtpSetCurrentDirectory)

BOOLAPI
FtpGetCurrentDirectoryA(
  _In_ HINTERNET hConnect,
  _Out_writes_(*lpdwCurrentDirectory) LPSTR lpszCurrentDirectory,
  _Inout_ LPDWORD lpdwCurrentDirectory);

BOOLAPI
FtpGetCurrentDirectoryW(
  _In_ HINTERNET hConnect,
  _Out_writes_(*lpdwCurrentDirectory) LPWSTR lpszCurrentDirectory,
  _Inout_ LPDWORD lpdwCurrentDirectory);

#define FtpGetCurrentDirectory WINELIB_NAME_AW(FtpGetCurrentDirectory)

#define MAX_GOPHER_DISPLAY_TEXT     128
#define MAX_GOPHER_SELECTOR_TEXT    256
#define MAX_GOPHER_HOST_NAME        INTERNET_MAX_HOST_NAME_LENGTH
#define MAX_GOPHER_LOCATOR_LENGTH   (1                                  \
                                    + MAX_GOPHER_DISPLAY_TEXT           \
                                    + 1                                 \
                                    + MAX_GOPHER_SELECTOR_TEXT          \
                                    + 1                                 \
                                    + MAX_GOPHER_HOST_NAME              \
                                    + 1                                 \
                                    + INTERNET_MAX_PORT_NUMBER_LENGTH   \
                                    + 1                                 \
                                    + 1                                 \
                                    + 2                                 \
                                    )


typedef struct {
    CHAR   DisplayString[MAX_GOPHER_DISPLAY_TEXT + 1];
    DWORD GopherType;
    DWORD SizeLow;
    DWORD SizeHigh;
    FILETIME LastModificationTime;
    CHAR   Locator[MAX_GOPHER_LOCATOR_LENGTH + 1];
} GOPHER_FIND_DATAA,* LPGOPHER_FIND_DATAA;

typedef struct {
    WCHAR  DisplayString[MAX_GOPHER_DISPLAY_TEXT + 1];
    DWORD GopherType;
    DWORD SizeLow;
    DWORD SizeHigh;
    FILETIME LastModificationTime;
    WCHAR  Locator[MAX_GOPHER_LOCATOR_LENGTH + 1];
} GOPHER_FIND_DATAW,* LPGOPHER_FIND_DATAW;

DECL_WINELIB_TYPE_AW(GOPHER_FIND_DATA)
DECL_WINELIB_TYPE_AW(LPGOPHER_FIND_DATA)

#define GOPHER_TYPE_TEXT_FILE       0x00000001
#define GOPHER_TYPE_DIRECTORY       0x00000002
#define GOPHER_TYPE_CSO             0x00000004
#define GOPHER_TYPE_ERROR           0x00000008
#define GOPHER_TYPE_MAC_BINHEX      0x00000010
#define GOPHER_TYPE_DOS_ARCHIVE     0x00000020
#define GOPHER_TYPE_UNIX_UUENCODED  0x00000040
#define GOPHER_TYPE_INDEX_SERVER    0x00000080
#define GOPHER_TYPE_TELNET          0x00000100
#define GOPHER_TYPE_BINARY          0x00000200
#define GOPHER_TYPE_REDUNDANT       0x00000400
#define GOPHER_TYPE_TN3270          0x00000800
#define GOPHER_TYPE_GIF             0x00001000
#define GOPHER_TYPE_IMAGE           0x00002000
#define GOPHER_TYPE_BITMAP          0x00004000
#define GOPHER_TYPE_MOVIE           0x00008000
#define GOPHER_TYPE_SOUND           0x00010000
#define GOPHER_TYPE_HTML            0x00020000
#define GOPHER_TYPE_PDF             0x00040000
#define GOPHER_TYPE_CALENDAR        0x00080000
#define GOPHER_TYPE_INLINE          0x00100000
#define GOPHER_TYPE_UNKNOWN         0x20000000
#define GOPHER_TYPE_ASK             0x40000000
#define GOPHER_TYPE_GOPHER_PLUS     0x80000000

#define IS_GOPHER_FILE(type)            (BOOL)(((type) & GOPHER_TYPE_FILE_MASK) != 0)
#define IS_GOPHER_DIRECTORY(type)       (BOOL)(((type) & GOPHER_TYPE_DIRECTORY) != 0)
#define IS_GOPHER_PHONE_SERVER(type)    (BOOL)(((type) & GOPHER_TYPE_CSO) != 0)
#define IS_GOPHER_ERROR(type)           (BOOL)(((type) & GOPHER_TYPE_ERROR) != 0)
#define IS_GOPHER_INDEX_SERVER(type)    (BOOL)(((type) & GOPHER_TYPE_INDEX_SERVER) != 0)
#define IS_GOPHER_TELNET_SESSION(type)  (BOOL)(((type) & GOPHER_TYPE_TELNET) != 0)
#define IS_GOPHER_BACKUP_SERVER(type)   (BOOL)(((type) & GOPHER_TYPE_REDUNDANT) != 0)
#define IS_GOPHER_TN3270_SESSION(type)  (BOOL)(((type) & GOPHER_TYPE_TN3270) != 0)
#define IS_GOPHER_ASK(type)             (BOOL)(((type) & GOPHER_TYPE_ASK) != 0)
#define IS_GOPHER_PLUS(type)            (BOOL)(((type) & GOPHER_TYPE_GOPHER_PLUS) != 0)
#define IS_GOPHER_TYPE_KNOWN(type)      (BOOL)(!((type) & GOPHER_TYPE_UNKNOWN))
#define GOPHER_TYPE_FILE_MASK       (GOPHER_TYPE_TEXT_FILE \
                                    | GOPHER_TYPE_MAC_BINHEX        \
                                    | GOPHER_TYPE_DOS_ARCHIVE       \
                                    | GOPHER_TYPE_UNIX_UUENCODED    \
                                    | GOPHER_TYPE_BINARY            \
                                    | GOPHER_TYPE_GIF               \
                                    | GOPHER_TYPE_IMAGE             \
                                    | GOPHER_TYPE_BITMAP            \
                                    | GOPHER_TYPE_MOVIE             \
                                    | GOPHER_TYPE_SOUND             \
                                    | GOPHER_TYPE_HTML              \
                                    | GOPHER_TYPE_PDF               \
                                    | GOPHER_TYPE_CALENDAR          \
                                    | GOPHER_TYPE_INLINE            \
                                    )


typedef struct {
    LPCSTR Comment;
    LPCSTR EmailAddress;
} GOPHER_ADMIN_ATTRIBUTE_TYPEA,* LPGOPHER_ADMIN_ATTRIBUTE_TYPEA;

typedef struct {
    LPCWSTR Comment;
    LPCWSTR EmailAddress;
} GOPHER_ADMIN_ATTRIBUTE_TYPEW,* LPGOPHER_ADMIN_ATTRIBUTE_TYPEW;

DECL_WINELIB_TYPE_AW(GOPHER_ADMIN_ATTRIBUTE_TYPE)
DECL_WINELIB_TYPE_AW(LPGOPHER_ADMIN_ATTRIBUTE_TYPE)

typedef struct {
    FILETIME DateAndTime;
} GOPHER_MOD_DATE_ATTRIBUTE_TYPE,* LPGOPHER_MOD_DATE_ATTRIBUTE_TYPE;

typedef struct {
    DWORD Ttl;
} GOPHER_TTL_ATTRIBUTE_TYPE,* LPGOPHER_TTL_ATTRIBUTE_TYPE;

typedef struct {
    INT Score;
} GOPHER_SCORE_ATTRIBUTE_TYPE,* LPGOPHER_SCORE_ATTRIBUTE_TYPE;

typedef struct {
    INT LowerBound;
    INT UpperBound;
} GOPHER_SCORE_RANGE_ATTRIBUTE_TYPE,* LPGOPHER_SCORE_RANGE_ATTRIBUTE_TYPE;

typedef struct {
    LPCSTR Site;
} GOPHER_SITE_ATTRIBUTE_TYPEA,* LPGOPHER_SITE_ATTRIBUTE_TYPEA;

typedef struct {
    LPCWSTR Site;
} GOPHER_SITE_ATTRIBUTE_TYPEW,* LPGOPHER_SITE_ATTRIBUTE_TYPEW;

DECL_WINELIB_TYPE_AW(GOPHER_SITE_ATTRIBUTE_TYPE)
DECL_WINELIB_TYPE_AW(LPGOPHER_SITE_ATTRIBUTE_TYPE)

typedef struct {
    LPCSTR Organization;
} GOPHER_ORGANIZATION_ATTRIBUTE_TYPEA,* LPGOPHER_ORGANIZATION_ATTRIBUTE_TYPEA;

typedef struct {
    LPCWSTR Organization;
} GOPHER_ORGANIZATION_ATTRIBUTE_TYPEW,* LPGOPHER_ORGANIZATION_ATTRIBUTE_TYPEW;

DECL_WINELIB_TYPE_AW(GOPHER_ORGANIZATION_ATTRIBUTE_TYPE)
DECL_WINELIB_TYPE_AW(LPGOPHER_ORGANIZATION_ATTRIBUTE_TYPE)

typedef struct {
    LPCSTR Location;
} GOPHER_LOCATION_ATTRIBUTE_TYPEA,* LPGOPHER_LOCATION_ATTRIBUTE_TYPEA;

typedef struct {
    LPCWSTR Location;
} GOPHER_LOCATION_ATTRIBUTE_TYPEW,* LPGOPHER_LOCATION_ATTRIBUTE_TYPEW;

DECL_WINELIB_TYPE_AW(GOPHER_LOCATION_ATTRIBUTE_TYPE)
DECL_WINELIB_TYPE_AW(LPGOPHER_LOCATION_ATTRIBUTE_TYPE)

typedef struct {
    INT DegreesNorth;
    INT MinutesNorth;
    INT SecondsNorth;
    INT DegreesEast;
    INT MinutesEast;
    INT SecondsEast;
} GOPHER_GEOGRAPHICAL_LOCATION_ATTRIBUTE_TYPE,* LPGOPHER_GEOGRAPHICAL_LOCATION_ATTRIBUTE_TYPE;

typedef struct {
    INT Zone;
} GOPHER_TIMEZONE_ATTRIBUTE_TYPE,* LPGOPHER_TIMEZONE_ATTRIBUTE_TYPE;

typedef struct {
    LPCSTR Provider;
} GOPHER_PROVIDER_ATTRIBUTE_TYPEA,* LPGOPHER_PROVIDER_ATTRIBUTE_TYPEA;

typedef struct {
    LPCWSTR Provider;
} GOPHER_PROVIDER_ATTRIBUTE_TYPEW,* LPGOPHER_PROVIDER_ATTRIBUTE_TYPEW;

DECL_WINELIB_TYPE_AW(GOPHER_PROVIDER_ATTRIBUTE_TYPE)
DECL_WINELIB_TYPE_AW(LPGOPHER_PROVIDER_ATTRIBUTE_TYPE)

typedef struct {
    LPCSTR Version;
} GOPHER_VERSION_ATTRIBUTE_TYPEA,* LPGOPHER_VERSION_ATTRIBUTE_TYPEA;

typedef struct {
    LPCWSTR Version;
} GOPHER_VERSION_ATTRIBUTE_TYPEW,* LPGOPHER_VERSION_ATTRIBUTE_TYPEW;

DECL_WINELIB_TYPE_AW(GOPHER_VERSION_ATTRIBUTE_TYPE)
DECL_WINELIB_TYPE_AW(LPGOPHER_VERSION_ATTRIBUTE_TYPE)

typedef struct {
    LPCSTR ShortAbstract;
    LPCSTR AbstractFile;
} GOPHER_ABSTRACT_ATTRIBUTE_TYPEA,* LPGOPHER_ABSTRACT_ATTRIBUTE_TYPEA;

typedef struct {
    LPCWSTR ShortAbstract;
    LPCWSTR AbstractFile;
} GOPHER_ABSTRACT_ATTRIBUTE_TYPEW,* LPGOPHER_ABSTRACT_ATTRIBUTE_TYPEW;

DECL_WINELIB_TYPE_AW(GOPHER_ABSTRACT_ATTRIBUTE_TYPE)
DECL_WINELIB_TYPE_AW(LPGOPHER_ABSTRACT_ATTRIBUTE_TYPE)

typedef struct {
    LPCSTR ContentType;
    LPCSTR Language;
    DWORD Size;
} GOPHER_VIEW_ATTRIBUTE_TYPEA,* LPGOPHER_VIEW_ATTRIBUTE_TYPEA;

typedef struct {
    LPCWSTR ContentType;
    LPCWSTR Language;
    DWORD Size;
} GOPHER_VIEW_ATTRIBUTE_TYPEW,* LPGOPHER_VIEW_ATTRIBUTE_TYPEW;

DECL_WINELIB_TYPE_AW(GOPHER_VIEW_ATTRIBUTE_TYPE)
DECL_WINELIB_TYPE_AW(LPGOPHER_VIEW_ATTRIBUTE_TYPE)

typedef struct {
    BOOL TreeWalk;
} GOPHER_VERONICA_ATTRIBUTE_TYPE,* LPGOPHER_VERONICA_ATTRIBUTE_TYPE;

typedef struct {
    LPCSTR QuestionType;
    LPCSTR QuestionText;
} GOPHER_ASK_ATTRIBUTE_TYPEA,* LPGOPHER_ASK_ATTRIBUTE_TYPEA;

typedef struct {
    LPCWSTR QuestionType;
    LPCWSTR QuestionText;
} GOPHER_ASK_ATTRIBUTE_TYPEW,* LPGOPHER_ASK_ATTRIBUTE_TYPEW;

DECL_WINELIB_TYPE_AW(GOPHER_ASK_ATTRIBUTE_TYPE)
DECL_WINELIB_TYPE_AW(LPGOPHER_ASK_ATTRIBUTE_TYPE)

typedef struct {
    LPCSTR Text;
} GOPHER_UNKNOWN_ATTRIBUTE_TYPEA,* LPGOPHER_UNKNOWN_ATTRIBUTE_TYPEA;

typedef struct {
    LPCWSTR Text;
} GOPHER_UNKNOWN_ATTRIBUTE_TYPEW,* LPGOPHER_UNKNOWN_ATTRIBUTE_TYPEW;

DECL_WINELIB_TYPE_AW(GOPHER_UNKNOWN_ATTRIBUTE_TYPE)
DECL_WINELIB_TYPE_AW(LPGOPHER_UNKNOWN_ATTRIBUTE_TYPE)

typedef struct {
    DWORD CategoryId;
    DWORD AttributeId;
    union {
        GOPHER_ADMIN_ATTRIBUTE_TYPEA Admin;
        GOPHER_MOD_DATE_ATTRIBUTE_TYPE ModDate;
        GOPHER_TTL_ATTRIBUTE_TYPE Ttl;
        GOPHER_SCORE_ATTRIBUTE_TYPE Score;
        GOPHER_SCORE_RANGE_ATTRIBUTE_TYPE ScoreRange;
        GOPHER_SITE_ATTRIBUTE_TYPEA Site;
        GOPHER_ORGANIZATION_ATTRIBUTE_TYPEA Organization;
        GOPHER_LOCATION_ATTRIBUTE_TYPEA Location;
        GOPHER_GEOGRAPHICAL_LOCATION_ATTRIBUTE_TYPE GeographicalLocation;
        GOPHER_TIMEZONE_ATTRIBUTE_TYPE TimeZone;
        GOPHER_PROVIDER_ATTRIBUTE_TYPEA Provider;
        GOPHER_VERSION_ATTRIBUTE_TYPEA Version;
        GOPHER_ABSTRACT_ATTRIBUTE_TYPEA Abstract;
        GOPHER_VIEW_ATTRIBUTE_TYPEA View;
        GOPHER_VERONICA_ATTRIBUTE_TYPE Veronica;
        GOPHER_ASK_ATTRIBUTE_TYPEA Ask;
        GOPHER_UNKNOWN_ATTRIBUTE_TYPEA Unknown;
    } AttributeType;
} GOPHER_ATTRIBUTE_TYPEA, *LPGOPHER_ATTRIBUTE_TYPEA;

typedef struct {
    DWORD CategoryId;
    DWORD AttributeId;
    union {
        GOPHER_ADMIN_ATTRIBUTE_TYPEW Admin;
        GOPHER_MOD_DATE_ATTRIBUTE_TYPE ModDate;
        GOPHER_TTL_ATTRIBUTE_TYPE Ttl;
        GOPHER_SCORE_ATTRIBUTE_TYPE Score;
        GOPHER_SCORE_RANGE_ATTRIBUTE_TYPE ScoreRange;
        GOPHER_SITE_ATTRIBUTE_TYPEW Site;
        GOPHER_ORGANIZATION_ATTRIBUTE_TYPEW Organization;
        GOPHER_LOCATION_ATTRIBUTE_TYPEW Location;
        GOPHER_GEOGRAPHICAL_LOCATION_ATTRIBUTE_TYPE GeographicalLocation;
        GOPHER_TIMEZONE_ATTRIBUTE_TYPE TimeZone;
        GOPHER_PROVIDER_ATTRIBUTE_TYPEW Provider;
        GOPHER_VERSION_ATTRIBUTE_TYPEW Version;
        GOPHER_ABSTRACT_ATTRIBUTE_TYPEW Abstract;
        GOPHER_VIEW_ATTRIBUTE_TYPEW View;
        GOPHER_VERONICA_ATTRIBUTE_TYPE Veronica;
        GOPHER_ASK_ATTRIBUTE_TYPEW Ask;
        GOPHER_UNKNOWN_ATTRIBUTE_TYPEW Unknown;
    } AttributeType;
} GOPHER_ATTRIBUTE_TYPEW, *LPGOPHER_ATTRIBUTE_TYPEW;

DECL_WINELIB_TYPE_AW(GOPHER_ATTRIBUTE_TYPE)
DECL_WINELIB_TYPE_AW(LPGOPHER_ATTRIBUTE_TYPE)

#define MAX_GOPHER_CATEGORY_NAME    128
#define MAX_GOPHER_ATTRIBUTE_NAME   128
#define MIN_GOPHER_ATTRIBUTE_LENGTH 256

#define GOPHER_INFO_CATEGORY        TEXT("+INFO")
#define GOPHER_ADMIN_CATEGORY       TEXT("+ADMIN")
#define GOPHER_VIEWS_CATEGORY       TEXT("+VIEWS")
#define GOPHER_ABSTRACT_CATEGORY    TEXT("+ABSTRACT")
#define GOPHER_VERONICA_CATEGORY    TEXT("+VERONICA")
#define GOPHER_ADMIN_ATTRIBUTE      TEXT("Admin")
#define GOPHER_MOD_DATE_ATTRIBUTE   TEXT("Mod-Date")
#define GOPHER_TTL_ATTRIBUTE        TEXT("TTL")
#define GOPHER_SCORE_ATTRIBUTE      TEXT("Score")
#define GOPHER_RANGE_ATTRIBUTE      TEXT("Score-range")
#define GOPHER_SITE_ATTRIBUTE       TEXT("Site")
#define GOPHER_ORG_ATTRIBUTE        TEXT("Org")
#define GOPHER_LOCATION_ATTRIBUTE   TEXT("Loc")
#define GOPHER_GEOG_ATTRIBUTE       TEXT("Geog")
#define GOPHER_TIMEZONE_ATTRIBUTE   TEXT("TZ")
#define GOPHER_PROVIDER_ATTRIBUTE   TEXT("Provider")
#define GOPHER_VERSION_ATTRIBUTE    TEXT("Version")
#define GOPHER_ABSTRACT_ATTRIBUTE   TEXT("Abstract")
#define GOPHER_VIEW_ATTRIBUTE       TEXT("View")
#define GOPHER_TREEWALK_ATTRIBUTE   TEXT("treewalk")

#define GOPHER_ATTRIBUTE_ID_BASE        0xabcccc00

#define GOPHER_CATEGORY_ID_ALL          (GOPHER_ATTRIBUTE_ID_BASE + 1)
#define GOPHER_CATEGORY_ID_INFO         (GOPHER_ATTRIBUTE_ID_BASE + 2)
#define GOPHER_CATEGORY_ID_ADMIN        (GOPHER_ATTRIBUTE_ID_BASE + 3)
#define GOPHER_CATEGORY_ID_VIEWS        (GOPHER_ATTRIBUTE_ID_BASE + 4)
#define GOPHER_CATEGORY_ID_ABSTRACT     (GOPHER_ATTRIBUTE_ID_BASE + 5)
#define GOPHER_CATEGORY_ID_VERONICA     (GOPHER_ATTRIBUTE_ID_BASE + 6)
#define GOPHER_CATEGORY_ID_ASK          (GOPHER_ATTRIBUTE_ID_BASE + 7)
#define GOPHER_CATEGORY_ID_UNKNOWN      (GOPHER_ATTRIBUTE_ID_BASE + 8)

#define GOPHER_ATTRIBUTE_ID_ALL         (GOPHER_ATTRIBUTE_ID_BASE + 9)
#define GOPHER_ATTRIBUTE_ID_ADMIN       (GOPHER_ATTRIBUTE_ID_BASE + 10)
#define GOPHER_ATTRIBUTE_ID_MOD_DATE    (GOPHER_ATTRIBUTE_ID_BASE + 11)
#define GOPHER_ATTRIBUTE_ID_TTL         (GOPHER_ATTRIBUTE_ID_BASE + 12)
#define GOPHER_ATTRIBUTE_ID_SCORE       (GOPHER_ATTRIBUTE_ID_BASE + 13)
#define GOPHER_ATTRIBUTE_ID_RANGE       (GOPHER_ATTRIBUTE_ID_BASE + 14)
#define GOPHER_ATTRIBUTE_ID_SITE        (GOPHER_ATTRIBUTE_ID_BASE + 15)
#define GOPHER_ATTRIBUTE_ID_ORG         (GOPHER_ATTRIBUTE_ID_BASE + 16)
#define GOPHER_ATTRIBUTE_ID_LOCATION    (GOPHER_ATTRIBUTE_ID_BASE + 17)
#define GOPHER_ATTRIBUTE_ID_GEOG        (GOPHER_ATTRIBUTE_ID_BASE + 18)
#define GOPHER_ATTRIBUTE_ID_TIMEZONE    (GOPHER_ATTRIBUTE_ID_BASE + 19)
#define GOPHER_ATTRIBUTE_ID_PROVIDER    (GOPHER_ATTRIBUTE_ID_BASE + 20)
#define GOPHER_ATTRIBUTE_ID_VERSION     (GOPHER_ATTRIBUTE_ID_BASE + 21)
#define GOPHER_ATTRIBUTE_ID_ABSTRACT    (GOPHER_ATTRIBUTE_ID_BASE + 22)
#define GOPHER_ATTRIBUTE_ID_VIEW        (GOPHER_ATTRIBUTE_ID_BASE + 23)
#define GOPHER_ATTRIBUTE_ID_TREEWALK    (GOPHER_ATTRIBUTE_ID_BASE + 24)
#define GOPHER_ATTRIBUTE_ID_UNKNOWN     (GOPHER_ATTRIBUTE_ID_BASE + 25)

BOOLAPI
GopherCreateLocatorA(
  _In_ LPCSTR lpszHost,
  _In_ INTERNET_PORT nServerPort,
  _In_opt_ LPCSTR lpszDisplayString,
  _In_opt_ LPCSTR lpszSelectorString,
  _In_ DWORD dwGopherType,
  _Out_writes_opt_(*lpdwBufferLength) LPSTR lpszLocator,
  _Inout_ LPDWORD lpdwBufferLength);

BOOLAPI
GopherCreateLocatorW(
  _In_ LPCWSTR lpszHost,
  _In_ INTERNET_PORT nServerPort,
  _In_opt_ LPCWSTR lpszDisplayString,
  _In_opt_ LPCWSTR lpszSelectorString,
  _In_ DWORD dwGopherType,
  _Out_writes_opt_(*lpdwBufferLength) LPWSTR lpszLocator,
  _Inout_ LPDWORD lpdwBufferLength);

#define GopherCreateLocator WINELIB_NAME_AW(GopherCreateLocator)

BOOLAPI GopherGetLocatorTypeA(_In_ LPCSTR, _Out_ LPDWORD);
BOOLAPI GopherGetLocatorTypeW(_In_ LPCWSTR, _Out_ LPDWORD);
#define GopherGetLocatorType WINELIB_NAME_AW(GopherGetLocatorType)

INTERNETAPI
HINTERNET
WINAPI
GopherFindFirstFileA(
  _In_ HINTERNET hConnect,
  _In_opt_ LPCSTR lpszLocator,
  _In_opt_ LPCSTR lpszSearchString,
  _Out_opt_ LPGOPHER_FIND_DATAA lpFindData,
  _In_ DWORD dwFlags,
  _In_opt_ DWORD_PTR dwContext);

INTERNETAPI
HINTERNET
WINAPI
GopherFindFirstFileW(
  _In_ HINTERNET hConnect,
  _In_opt_ LPCWSTR lpszLocator,
  _In_opt_ LPCWSTR lpszSearchString,
  _Out_opt_ LPGOPHER_FIND_DATAW lpFindData,
  _In_ DWORD dwFlags,
  _In_opt_ DWORD_PTR dwContext);

#define GopherFindFirstFile WINELIB_NAME_AW(GopherFindFirstFile)

INTERNETAPI
HINTERNET
WINAPI
GopherOpenFileA(
  _In_ HINTERNET,
  _In_ LPCSTR,
  _In_opt_ LPCSTR,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

INTERNETAPI
HINTERNET
WINAPI
GopherOpenFileW(
  _In_ HINTERNET,
  _In_ LPCWSTR,
  _In_opt_ LPCWSTR,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

#define GopherOpenFile WINELIB_NAME_AW(GopherOpenFile)

typedef BOOL
(CALLBACK *GOPHER_ATTRIBUTE_ENUMERATORA)(
  _In_ LPGOPHER_ATTRIBUTE_TYPEA,
  _In_ DWORD);

typedef BOOL
(CALLBACK *GOPHER_ATTRIBUTE_ENUMERATORW)(
  _In_ LPGOPHER_ATTRIBUTE_TYPEW,
  _In_ DWORD);

DECL_WINELIB_TYPE_AW(GOPHER_ATTRIBUTE_ENUMERATOR)

BOOLAPI
GopherGetAttributeA(
  _In_ HINTERNET hConnect,
  _In_ LPCSTR lpszLocator,
  _In_opt_ LPCSTR lpszAttributeName,
  _At_((LPSTR) lpBuffer, _Out_writes_(dwBufferLength)) LPBYTE lpBuffer,
  _In_ DWORD dwBufferLength,
  _Out_ LPDWORD lpdwCharactersReturned,
  _In_opt_ GOPHER_ATTRIBUTE_ENUMERATORA lpfnEnumerator,
  _In_opt_ DWORD_PTR dwContext);

BOOLAPI
GopherGetAttributeW(
  _In_ HINTERNET hConnect,
  _In_ LPCWSTR lpszLocator,
  _In_opt_ LPCWSTR lpszAttributeName,
  _At_((LPWSTR) lpBuffer, _Out_writes_(dwBufferLength)) LPBYTE lpBuffer,
  _In_ DWORD dwBufferLength,
  _Out_ LPDWORD lpdwCharactersReturned,
  _In_opt_ GOPHER_ATTRIBUTE_ENUMERATORW lpfnEnumerator,
  _In_opt_ DWORD_PTR dwContext);

#define GopherGetAttribute WINELIB_NAME_AW(GopherGetAttribute)

#define HTTP_MAJOR_VERSION      1
#define HTTP_MINOR_VERSION      0
#define HTTP_VERSION            TEXT("HTTP/1.0")
#define HTTP_QUERY_MIME_VERSION                 0
#define HTTP_QUERY_CONTENT_TYPE                 1
#define HTTP_QUERY_CONTENT_TRANSFER_ENCODING    2
#define HTTP_QUERY_CONTENT_ID                   3
#define HTTP_QUERY_CONTENT_DESCRIPTION          4
#define HTTP_QUERY_CONTENT_LENGTH               5
#define HTTP_QUERY_CONTENT_LANGUAGE             6
#define HTTP_QUERY_ALLOW                        7
#define HTTP_QUERY_PUBLIC                       8
#define HTTP_QUERY_DATE                         9
#define HTTP_QUERY_EXPIRES                      10
#define HTTP_QUERY_LAST_MODIFIED                11
#define HTTP_QUERY_MESSAGE_ID                   12
#define HTTP_QUERY_URI                          13
#define HTTP_QUERY_DERIVED_FROM                 14
#define HTTP_QUERY_COST                         15
#define HTTP_QUERY_LINK                         16
#define HTTP_QUERY_PRAGMA                       17
#define HTTP_QUERY_VERSION                      18
#define HTTP_QUERY_STATUS_CODE                  19
#define HTTP_QUERY_STATUS_TEXT                  20
#define HTTP_QUERY_RAW_HEADERS                  21
#define HTTP_QUERY_RAW_HEADERS_CRLF             22
#define HTTP_QUERY_CONNECTION                   23
#define HTTP_QUERY_ACCEPT                       24
#define HTTP_QUERY_ACCEPT_CHARSET               25
#define HTTP_QUERY_ACCEPT_ENCODING              26
#define HTTP_QUERY_ACCEPT_LANGUAGE              27
#define HTTP_QUERY_AUTHORIZATION                28
#define HTTP_QUERY_CONTENT_ENCODING             29
#define HTTP_QUERY_FORWARDED                    30
#define HTTP_QUERY_FROM                         31
#define HTTP_QUERY_IF_MODIFIED_SINCE            32
#define HTTP_QUERY_LOCATION                     33
#define HTTP_QUERY_ORIG_URI                     34
#define HTTP_QUERY_REFERER                      35
#define HTTP_QUERY_RETRY_AFTER                  36
#define HTTP_QUERY_SERVER                       37
#define HTTP_QUERY_TITLE                        38
#define HTTP_QUERY_USER_AGENT                   39
#define HTTP_QUERY_WWW_AUTHENTICATE             40
#define HTTP_QUERY_PROXY_AUTHENTICATE           41
#define HTTP_QUERY_ACCEPT_RANGES                42
#define HTTP_QUERY_SET_COOKIE                   43
#define HTTP_QUERY_COOKIE                       44
#define HTTP_QUERY_REQUEST_METHOD               45
#define HTTP_QUERY_REFRESH                      46
#define HTTP_QUERY_CONTENT_DISPOSITION          47
#define HTTP_QUERY_AGE                          48
#define HTTP_QUERY_CACHE_CONTROL                49
#define HTTP_QUERY_CONTENT_BASE                 50
#define HTTP_QUERY_CONTENT_LOCATION             51
#define HTTP_QUERY_CONTENT_MD5                  52
#define HTTP_QUERY_CONTENT_RANGE                53
#define HTTP_QUERY_ETAG                         54
#define HTTP_QUERY_HOST                         55
#define HTTP_QUERY_IF_MATCH                     56
#define HTTP_QUERY_IF_NONE_MATCH                57
#define HTTP_QUERY_IF_RANGE                     58
#define HTTP_QUERY_IF_UNMODIFIED_SINCE          59
#define HTTP_QUERY_MAX_FORWARDS                 60
#define HTTP_QUERY_PROXY_AUTHORIZATION          61
#define HTTP_QUERY_RANGE                        62
#define HTTP_QUERY_TRANSFER_ENCODING            63
#define HTTP_QUERY_UPGRADE                      64
#define HTTP_QUERY_VARY                         65
#define HTTP_QUERY_VIA                          66
#define HTTP_QUERY_WARNING                      67
#define HTTP_QUERY_EXPECT                       68
#define HTTP_QUERY_PROXY_CONNECTION             69
#define HTTP_QUERY_UNLESS_MODIFIED_SINCE        70
#define HTTP_QUERY_ECHO_REQUEST                 71
#define HTTP_QUERY_ECHO_REPLY                   72
#define HTTP_QUERY_ECHO_HEADERS                 73
#define HTTP_QUERY_ECHO_HEADERS_CRLF            74
#define HTTP_QUERY_PROXY_SUPPORT                75
#define HTTP_QUERY_AUTHENTICATION_INFO          76
#define HTTP_QUERY_PASSPORT_URLS                77
#define HTTP_QUERY_PASSPORT_CONFIG              78
#define HTTP_QUERY_MAX                          78
#define HTTP_QUERY_CUSTOM                       65535
#define HTTP_QUERY_FLAG_REQUEST_HEADERS         0x80000000
#define HTTP_QUERY_FLAG_SYSTEMTIME              0x40000000
#define HTTP_QUERY_FLAG_NUMBER                  0x20000000
#define HTTP_QUERY_FLAG_COALESCE                0x10000000
#define HTTP_QUERY_MODIFIER_FLAGS_MASK          (HTTP_QUERY_FLAG_REQUEST_HEADERS \
                                                | HTTP_QUERY_FLAG_SYSTEMTIME        \
                                                | HTTP_QUERY_FLAG_NUMBER            \
                                                | HTTP_QUERY_FLAG_COALESCE          \
                                                )
#define HTTP_QUERY_HEADER_MASK                  (~HTTP_QUERY_MODIFIER_FLAGS_MASK)

#define HTTP_STATUS_CONTINUE            100
#define HTTP_STATUS_SWITCH_PROTOCOLS    101
#define HTTP_STATUS_OK                  200
#define HTTP_STATUS_CREATED             201
#define HTTP_STATUS_ACCEPTED            202
#define HTTP_STATUS_PARTIAL             203
#define HTTP_STATUS_NO_CONTENT          204
#define HTTP_STATUS_RESET_CONTENT       205
#define HTTP_STATUS_PARTIAL_CONTENT     206
#define HTTP_STATUS_AMBIGUOUS           300
#define HTTP_STATUS_MOVED               301
#define HTTP_STATUS_REDIRECT            302
#define HTTP_STATUS_REDIRECT_METHOD     303
#define HTTP_STATUS_NOT_MODIFIED        304
#define HTTP_STATUS_USE_PROXY           305
#define HTTP_STATUS_REDIRECT_KEEP_VERB  307
#define HTTP_STATUS_BAD_REQUEST         400
#define HTTP_STATUS_DENIED              401
#define HTTP_STATUS_PAYMENT_REQ         402
#define HTTP_STATUS_FORBIDDEN           403
#define HTTP_STATUS_NOT_FOUND           404
#define HTTP_STATUS_BAD_METHOD          405
#define HTTP_STATUS_NONE_ACCEPTABLE     406
#define HTTP_STATUS_PROXY_AUTH_REQ      407
#define HTTP_STATUS_REQUEST_TIMEOUT     408
#define HTTP_STATUS_CONFLICT            409
#define HTTP_STATUS_GONE                410
#define HTTP_STATUS_LENGTH_REQUIRED     411
#define HTTP_STATUS_PRECOND_FAILED      412
#define HTTP_STATUS_REQUEST_TOO_LARGE   413
#define HTTP_STATUS_URI_TOO_LONG        414
#define HTTP_STATUS_UNSUPPORTED_MEDIA   415
#define HTTP_STATUS_SERVER_ERROR        500
#define HTTP_STATUS_NOT_SUPPORTED       501
#define HTTP_STATUS_BAD_GATEWAY         502
#define HTTP_STATUS_SERVICE_UNAVAIL     503
#define HTTP_STATUS_GATEWAY_TIMEOUT     504
#define HTTP_STATUS_VERSION_NOT_SUP     505
#define HTTP_STATUS_FIRST               HTTP_STATUS_CONTINUE
#define HTTP_STATUS_LAST                HTTP_STATUS_VERSION_NOT_SUP


INTERNETAPI
HINTERNET
WINAPI
HttpOpenRequestA(
  _In_ HINTERNET hConnect,
  _In_opt_ LPCSTR lpszVerb,
  _In_opt_ LPCSTR lpszObjectName,
  _In_opt_ LPCSTR lpszVersion,
  _In_opt_ LPCSTR lpszReferrer,
  _In_opt_z_ LPCSTR FAR * lplpszAcceptTypes,
  _In_ DWORD dwFlags,
  _In_opt_ DWORD_PTR dwContext);

INTERNETAPI
HINTERNET
WINAPI HttpOpenRequestW(
  _In_ HINTERNET hConnect,
  _In_opt_ LPCWSTR lpszVerb,
  _In_opt_ LPCWSTR lpszObjectName,
  _In_opt_ LPCWSTR lpszVersion,
  _In_opt_ LPCWSTR lpszReferrer,
  _In_opt_z_ LPCWSTR FAR * lplpszAcceptTypes,
  _In_ DWORD dwFlags,
  _In_opt_ DWORD_PTR dwContext);

#define HttpOpenRequest WINELIB_NAME_AW(HttpOpenRequest)

BOOLAPI
HttpAddRequestHeadersA(
  _In_ HINTERNET hRequest,
  _When_(dwHeadersLength == (DWORD) - 1, _In_z_)
  _When_(dwHeadersLength != (DWORD) - 1, _In_reads_(dwHeadersLength))
    LPCSTR lpszHeaders,
  _In_ DWORD dwHeadersLength,
  _In_ DWORD dwModifiers);

BOOLAPI
HttpAddRequestHeadersW(
  _In_ HINTERNET hRequest,
  _When_(dwHeadersLength == (DWORD) - 1, _In_z_)
  _When_(dwHeadersLength != (DWORD) - 1, _In_reads_(dwHeadersLength))
    LPCWSTR lpszHeaders,
  _In_ DWORD dwHeadersLength,
  _In_ DWORD dwModifiers);

#define HttpAddRequestHeaders WINELIB_NAME_AW(HttpAddRequestHeaders)

#define HTTP_ADDREQ_INDEX_MASK      0x0000FFFF
#define HTTP_ADDREQ_FLAGS_MASK      0xFFFF0000
#define HTTP_ADDREQ_FLAG_ADD_IF_NEW 0x10000000
#define HTTP_ADDREQ_FLAG_ADD        0x20000000
#define HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA       0x40000000
#define HTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON   0x01000000
#define HTTP_ADDREQ_FLAG_COALESCE                  HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA
#define HTTP_ADDREQ_FLAG_REPLACE    0x80000000

BOOLAPI
HttpSendRequestA(
  _In_ HINTERNET hRequest,
  _In_reads_opt_(dwHeadersLength) LPCSTR lpszHeaders,
  _In_ DWORD dwHeadersLength,
  _In_reads_bytes_opt_(dwOptionalLength) LPVOID lpOptional,
  _In_ DWORD dwOptionalLength);

BOOLAPI
HttpSendRequestW(
  _In_ HINTERNET hRequest,
  _In_reads_opt_(dwHeadersLength) LPCWSTR lpszHeaders,
  _In_ DWORD dwHeadersLength,
  _In_reads_bytes_opt_(dwOptionalLength) LPVOID lpOptional,
  _In_ DWORD dwOptionalLength);

#define HttpSendRequest WINELIB_NAME_AW(HttpSendRequest)

BOOLAPI
HttpSendRequestExA(
  _In_ HINTERNET,
  _In_opt_ LPINTERNET_BUFFERSA,
  _Out_opt_ LPINTERNET_BUFFERSA,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

BOOLAPI
HttpSendRequestExW(
  _In_ HINTERNET,
  _In_opt_ LPINTERNET_BUFFERSW,
  _Out_opt_ LPINTERNET_BUFFERSW,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

#define HttpSendRequestEx WINELIB_NAME_AW(HttpSendRequestEx)

#define HSR_ASYNC       WININET_API_FLAG_ASYNC
#define HSR_SYNC        WININET_API_FLAG_SYNC
#define HSR_USE_CONTEXT WININET_API_FLAG_USE_CONTEXT
#define HSR_INITIATE    0x00000008
#define HSR_DOWNLOAD    0x00000010
#define HSR_CHUNKED     0x00000020

BOOLAPI
HttpEndRequestA(
  _In_ HINTERNET,
  _Out_opt_ LPINTERNET_BUFFERSA,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

BOOLAPI
HttpEndRequestW(
  _In_ HINTERNET,
  _Out_opt_ LPINTERNET_BUFFERSW,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

#define HttpEndRequest WINELIB_NAME_AW(HttpEndRequest)

BOOLAPI
HttpQueryInfoA(
  _In_ HINTERNET hRequest,
  _In_ DWORD dwInfoLevel,
  _Inout_updates_bytes_to_opt_(*lpdwBufferLength, *lpdwBufferLength) __out_data_source(NETWORK) LPVOID lpBuffer,
  _Inout_ LPDWORD lpdwBufferLength,
  _Inout_opt_ LPDWORD lpdwIndex);

BOOLAPI
HttpQueryInfoW(
  _In_ HINTERNET hRequest,
  _In_ DWORD dwInfoLevel,
  _Inout_updates_bytes_to_opt_(*lpdwBufferLength, *lpdwBufferLength) __out_data_source(NETWORK) LPVOID lpBuffer,
  _Inout_ LPDWORD lpdwBufferLength,
  _Inout_opt_ LPDWORD lpdwIndex);

#define HttpQueryInfo WINELIB_NAME_AW(HttpQueryInfo)

typedef enum {
    COOKIE_STATE_UNKNOWN,
    COOKIE_STATE_ACCEPT,
    COOKIE_STATE_PROMPT,
    COOKIE_STATE_LEASH,
    COOKIE_STATE_DOWNGRADE,
    COOKIE_STATE_REJECT,
    COOKIE_STATE_MAX = COOKIE_STATE_REJECT
} InternetCookieState;

BOOLAPI InternetClearAllPerSiteCookieDecisions(VOID);

BOOLAPI
InternetEnumPerSiteCookieDecisionA(
  _Out_writes_to_(*pcSiteNameSize, *pcSiteNameSize) LPSTR pszSiteName,
  _Inout_ ULONG *pcSiteNameSize,
  _Out_ ULONG *pdwDecision,
  _In_ ULONG dwIndex);

BOOLAPI
InternetEnumPerSiteCookieDecisionW(
  _Out_writes_to_(*pcSiteNameSize, *pcSiteNameSize) LPWSTR pszSiteName,
  _Inout_ ULONG *pcSiteNameSize,
  _Out_ ULONG *pdwDecision,
  _In_ ULONG dwIndex);

#define InternetEnumPerSiteCookieDecision WINELIB_NAME_AW(InternetEnumPerSiteCookieDecision)

#define INTERNET_COOKIE_IS_SECURE       0x00000001
#define INTERNET_COOKIE_IS_SESSION      0x00000002
#define INTERNET_COOKIE_THIRD_PARTY     0x00000010
#define INTERNET_COOKIE_PROMPT_REQUIRED 0x00000020
#define INTERNET_COOKIE_EVALUATE_P3P    0x00000040
#define INTERNET_COOKIE_APPLY_P3P       0x00000080
#define INTERNET_COOKIE_P3P_ENABLED     0x00000100
#define INTERNET_COOKIE_IS_RESTRICTED   0x00000200
#define INTERNET_COOKIE_IE6             0x00000400
#define INTERNET_COOKIE_IS_LEGACY       0x00000800
#define INTERNET_COOKIE_HTTPONLY        0x00002000

BOOLAPI
InternetGetCookieExA(
  _In_ LPCSTR lpszUrl,
  _In_opt_ LPCSTR lpszCookieName,
  _In_reads_opt_(*lpdwSize) LPSTR lpszCookieData,
  _Inout_ LPDWORD lpdwSize,
  _In_ DWORD dwFlags,
  _Reserved_ LPVOID lpReserved);

BOOLAPI
InternetGetCookieExW(
  _In_ LPCWSTR lpszUrl,
  _In_opt_ LPCWSTR lpszCookieName,
  _In_reads_opt_(*lpdwSize) LPWSTR lpszCookieData,
  _Inout_ LPDWORD lpdwSize,
  _In_ DWORD dwFlags,
  _Reserved_ LPVOID lpReserved);

#define InternetGetCookieEx WINELIB_NAME_AW(InternetGetCookieEx)

DWORD
WINAPI
InternetSetCookieExA(
  _In_ LPCSTR,
  _In_opt_ LPCSTR,
  _In_ LPCSTR,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

DWORD
WINAPI
InternetSetCookieExW(
  _In_ LPCWSTR,
  _In_opt_ LPCWSTR,
  _In_ LPCWSTR,
  _In_ DWORD,
  _In_opt_ DWORD_PTR);

#define InternetSetCookieEx WINELIB_NAME_AW(InternetSetCookieEx)

BOOLAPI InternetGetPerSiteCookieDecisionA(_In_ LPCSTR, _Out_ ULONG *);
BOOLAPI InternetGetPerSiteCookieDecisionW(_In_ LPCWSTR, _Out_ ULONG *);
#define InternetGetPerSiteCookieDecision WINELIB_NAME_AW(InternetGetPerSiteCookieDecision)

BOOLAPI InternetSetPerSiteCookieDecisionA(_In_ LPCSTR, _In_ DWORD);
BOOLAPI InternetSetPerSiteCookieDecisionW(_In_ LPCWSTR, _In_ DWORD);
#define InternetSetPerSiteCookieDecision WINELIB_NAME_AW(InternetSetPerSiteCookieDecision)

BOOLAPI InternetSetCookieA(_In_ LPCSTR, _In_opt_ LPCSTR, _In_ LPCSTR);
BOOLAPI InternetSetCookieW(_In_ LPCWSTR, _In_opt_ LPCWSTR, _In_ LPCWSTR);
#define InternetSetCookie  WINELIB_NAME_AW(InternetSetCookie)

BOOLAPI
InternetGetCookieA(
  _In_ LPCSTR lpszUrl,
  _In_opt_ LPCSTR lpszCookieName,
  _Out_writes_opt_(*lpdwSize) LPSTR lpszCookieData,
  _Inout_ LPDWORD lpdwSize);

BOOLAPI
InternetGetCookieW(
  _In_ LPCWSTR lpszUrl,
  _In_opt_ LPCWSTR lpszCookieName,
  _Out_writes_opt_(*lpdwSize) LPWSTR lpszCookieData,
  _Inout_ LPDWORD lpdwSize);

#define InternetGetCookie WINELIB_NAME_AW(InternetGetCookie)

INTERNETAPI DWORD WINAPI InternetAttemptConnect(_In_ DWORD);

BOOLAPI InternetCheckConnectionA(_In_ LPCSTR, _In_ DWORD, _In_ DWORD);
BOOLAPI InternetCheckConnectionW(_In_ LPCWSTR, _In_ DWORD, _In_ DWORD);
#define InternetCheckConnection  WINELIB_NAME_AW(InternetCheckConnection)

#define FLAG_ICC_FORCE_CONNECTION       0x00000001

#define FLAGS_ERROR_UI_FILTER_FOR_ERRORS        0x01
#define FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS     0x02
#define FLAGS_ERROR_UI_FLAGS_GENERATE_DATA      0x04
#define FLAGS_ERROR_UI_FLAGS_NO_UI              0x08
#define FLAGS_ERROR_UI_SERIALIZE_DIALOGS        0x10

DWORD InternetAuthNotifyCallback ( DWORD_PTR ,DWORD ,LPVOID );
typedef DWORD (CALLBACK *PFN_AUTH_NOTIFY) (DWORD_PTR,DWORD,LPVOID);

typedef struct
{
    DWORD            cbStruct;
    DWORD            dwOptions;
    PFN_AUTH_NOTIFY  pfnNotify;
    DWORD_PTR        dwContext;
}
INTERNET_AUTH_NOTIFY_DATA;


INTERNETAPI
DWORD
WINAPI
InternetErrorDlg(
  _In_ HWND,
  _Inout_opt_ HINTERNET,
  _In_ DWORD,
  _In_ DWORD,
  _Inout_opt_ LPVOID *);

INTERNETAPI
DWORD
WINAPI
InternetConfirmZoneCrossingA(
  _In_ HWND,
  _In_ LPSTR,
  _In_ LPSTR,
  _In_ BOOL);

INTERNETAPI
DWORD
WINAPI
InternetConfirmZoneCrossingW(
  _In_ HWND,
  _In_ LPWSTR,
  _In_ LPWSTR,
  _In_ BOOL);

#define InternetConfirmZoneCrossing WINELIB_NAME_AW(InternetConfirmZoneCrossing)

#define PRIVACY_TEMPLATE_NO_COOKIES  0
#define PRIVACY_TEMPLATE_HIGH        1
#define PRIVACY_TEMPLATE_MEDIUM_HIGH 2
#define PRIVACY_TEMPLATE_MEDIUM      3
#define PRIVACY_TEMPLATE_MEDIUM_LOW  4
#define PRIVACY_TEMPLATE_LOW         5
#define PRIVACY_TEMPLATE_CUSTOM      100
#define PRIVACY_TEMPLATE_ADVANCED    101

#define PRIVACY_TEMPLATE_MAX         PRIVACY_TEMPLATE_LOW

#define PRIVACY_TYPE_FIRST_PARTY 0
#define PRIVACY_TYPE_THIRD_PARTY 1

INTERNETAPI
DWORD
WINAPI
PrivacySetZonePreferenceW(
  _In_ DWORD,
  _In_ DWORD,
  _In_ DWORD,
  _In_opt_ LPCWSTR);

INTERNETAPI
DWORD
WINAPI
PrivacyGetZonePreferenceW(
  _In_ DWORD dwZone,
  _In_ DWORD dwType,
  _Out_opt_ LPDWORD pdwTemplate,
  _Out_writes_opt_(*pdwBufferLength) LPWSTR pszBuffer,
  _Inout_opt_ LPDWORD pdwBufferLength);

#define INTERNET_ERROR_BASE                     12000

#define ERROR_INTERNET_OUT_OF_HANDLES           (INTERNET_ERROR_BASE + 1)
#define ERROR_INTERNET_TIMEOUT                  (INTERNET_ERROR_BASE + 2)
#define ERROR_INTERNET_EXTENDED_ERROR           (INTERNET_ERROR_BASE + 3)
#define ERROR_INTERNET_INTERNAL_ERROR           (INTERNET_ERROR_BASE + 4)
#define ERROR_INTERNET_INVALID_URL              (INTERNET_ERROR_BASE + 5)
#define ERROR_INTERNET_UNRECOGNIZED_SCHEME      (INTERNET_ERROR_BASE + 6)
#define ERROR_INTERNET_NAME_NOT_RESOLVED        (INTERNET_ERROR_BASE + 7)
#define ERROR_INTERNET_PROTOCOL_NOT_FOUND       (INTERNET_ERROR_BASE + 8)
#define ERROR_INTERNET_INVALID_OPTION           (INTERNET_ERROR_BASE + 9)
#define ERROR_INTERNET_BAD_OPTION_LENGTH        (INTERNET_ERROR_BASE + 10)
#define ERROR_INTERNET_OPTION_NOT_SETTABLE      (INTERNET_ERROR_BASE + 11)
#define ERROR_INTERNET_SHUTDOWN                 (INTERNET_ERROR_BASE + 12)
#define ERROR_INTERNET_INCORRECT_USER_NAME      (INTERNET_ERROR_BASE + 13)
#define ERROR_INTERNET_INCORRECT_PASSWORD       (INTERNET_ERROR_BASE + 14)
#define ERROR_INTERNET_LOGIN_FAILURE            (INTERNET_ERROR_BASE + 15)
#define ERROR_INTERNET_INVALID_OPERATION        (INTERNET_ERROR_BASE + 16)
#define ERROR_INTERNET_OPERATION_CANCELLED      (INTERNET_ERROR_BASE + 17)
#define ERROR_INTERNET_INCORRECT_HANDLE_TYPE    (INTERNET_ERROR_BASE + 18)
#define ERROR_INTERNET_INCORRECT_HANDLE_STATE   (INTERNET_ERROR_BASE + 19)
#define ERROR_INTERNET_NOT_PROXY_REQUEST        (INTERNET_ERROR_BASE + 20)
#define ERROR_INTERNET_REGISTRY_VALUE_NOT_FOUND (INTERNET_ERROR_BASE + 21)
#define ERROR_INTERNET_BAD_REGISTRY_PARAMETER   (INTERNET_ERROR_BASE + 22)
#define ERROR_INTERNET_NO_DIRECT_ACCESS         (INTERNET_ERROR_BASE + 23)
#define ERROR_INTERNET_NO_CONTEXT               (INTERNET_ERROR_BASE + 24)
#define ERROR_INTERNET_NO_CALLBACK              (INTERNET_ERROR_BASE + 25)
#define ERROR_INTERNET_REQUEST_PENDING          (INTERNET_ERROR_BASE + 26)
#define ERROR_INTERNET_INCORRECT_FORMAT         (INTERNET_ERROR_BASE + 27)
#define ERROR_INTERNET_ITEM_NOT_FOUND           (INTERNET_ERROR_BASE + 28)
#define ERROR_INTERNET_CANNOT_CONNECT           (INTERNET_ERROR_BASE + 29)
#define ERROR_INTERNET_CONNECTION_ABORTED       (INTERNET_ERROR_BASE + 30)
#define ERROR_INTERNET_CONNECTION_RESET         (INTERNET_ERROR_BASE + 31)
#define ERROR_INTERNET_FORCE_RETRY              (INTERNET_ERROR_BASE + 32)
#define ERROR_INTERNET_INVALID_PROXY_REQUEST    (INTERNET_ERROR_BASE + 33)
#define ERROR_INTERNET_NEED_UI                  (INTERNET_ERROR_BASE + 34)
#define ERROR_INTERNET_HANDLE_EXISTS            (INTERNET_ERROR_BASE + 36)
#define ERROR_INTERNET_SEC_CERT_DATE_INVALID    (INTERNET_ERROR_BASE + 37)
#define ERROR_INTERNET_SEC_CERT_CN_INVALID      (INTERNET_ERROR_BASE + 38)
#define ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR   (INTERNET_ERROR_BASE + 39)
#define ERROR_INTERNET_HTTPS_TO_HTTP_ON_REDIR   (INTERNET_ERROR_BASE + 40)
#define ERROR_INTERNET_MIXED_SECURITY           (INTERNET_ERROR_BASE + 41)
#define ERROR_INTERNET_CHG_POST_IS_NON_SECURE   (INTERNET_ERROR_BASE + 42)
#define ERROR_INTERNET_POST_IS_NON_SECURE       (INTERNET_ERROR_BASE + 43)
#define ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED  (INTERNET_ERROR_BASE + 44)
#define ERROR_INTERNET_INVALID_CA               (INTERNET_ERROR_BASE + 45)
#define ERROR_INTERNET_CLIENT_AUTH_NOT_SETUP    (INTERNET_ERROR_BASE + 46)
#define ERROR_INTERNET_ASYNC_THREAD_FAILED      (INTERNET_ERROR_BASE + 47)
#define ERROR_INTERNET_REDIRECT_SCHEME_CHANGE   (INTERNET_ERROR_BASE + 48)
#define ERROR_INTERNET_DIALOG_PENDING           (INTERNET_ERROR_BASE + 49)
#define ERROR_INTERNET_RETRY_DIALOG             (INTERNET_ERROR_BASE + 50)
#define ERROR_INTERNET_HTTPS_HTTP_SUBMIT_REDIR  (INTERNET_ERROR_BASE + 52)
#define ERROR_INTERNET_INSERT_CDROM             (INTERNET_ERROR_BASE + 53)
#define ERROR_INTERNET_FORTEZZA_LOGIN_NEEDED    (INTERNET_ERROR_BASE + 54)
#define ERROR_INTERNET_SEC_CERT_ERRORS          (INTERNET_ERROR_BASE + 55)
#define ERROR_INTERNET_SEC_CERT_NO_REV          (INTERNET_ERROR_BASE + 56)
#define ERROR_INTERNET_SEC_CERT_REV_FAILED      (INTERNET_ERROR_BASE + 57)
#define ERROR_INTERNET_SEC_CERT_WEAK_SIGNATURE  (INTERNET_ERROR_BASE + 62)
#define ERROR_FTP_TRANSFER_IN_PROGRESS          (INTERNET_ERROR_BASE + 110)
#define ERROR_FTP_DROPPED                       (INTERNET_ERROR_BASE + 111)
#define ERROR_FTP_NO_PASSIVE_MODE               (INTERNET_ERROR_BASE + 112)
#define ERROR_GOPHER_PROTOCOL_ERROR             (INTERNET_ERROR_BASE + 130)
#define ERROR_GOPHER_NOT_FILE                   (INTERNET_ERROR_BASE + 131)
#define ERROR_GOPHER_DATA_ERROR                 (INTERNET_ERROR_BASE + 132)
#define ERROR_GOPHER_END_OF_DATA                (INTERNET_ERROR_BASE + 133)
#define ERROR_GOPHER_INVALID_LOCATOR            (INTERNET_ERROR_BASE + 134)
#define ERROR_GOPHER_INCORRECT_LOCATOR_TYPE     (INTERNET_ERROR_BASE + 135)
#define ERROR_GOPHER_NOT_GOPHER_PLUS            (INTERNET_ERROR_BASE + 136)
#define ERROR_GOPHER_ATTRIBUTE_NOT_FOUND        (INTERNET_ERROR_BASE + 137)
#define ERROR_GOPHER_UNKNOWN_LOCATOR            (INTERNET_ERROR_BASE + 138)
#define ERROR_HTTP_HEADER_NOT_FOUND             (INTERNET_ERROR_BASE + 150)
#define ERROR_HTTP_DOWNLEVEL_SERVER             (INTERNET_ERROR_BASE + 151)
#define ERROR_HTTP_INVALID_SERVER_RESPONSE      (INTERNET_ERROR_BASE + 152)
#define ERROR_HTTP_INVALID_HEADER               (INTERNET_ERROR_BASE + 153)
#define ERROR_HTTP_INVALID_QUERY_REQUEST        (INTERNET_ERROR_BASE + 154)
#define ERROR_HTTP_HEADER_ALREADY_EXISTS        (INTERNET_ERROR_BASE + 155)
#define ERROR_HTTP_REDIRECT_FAILED              (INTERNET_ERROR_BASE + 156)
#define ERROR_HTTP_NOT_REDIRECTED               (INTERNET_ERROR_BASE + 160)
#define ERROR_HTTP_COOKIE_NEEDS_CONFIRMATION    (INTERNET_ERROR_BASE + 161)
#define ERROR_HTTP_COOKIE_DECLINED              (INTERNET_ERROR_BASE + 162)
#define ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION  (INTERNET_ERROR_BASE + 168)
#define ERROR_INTERNET_SECURITY_CHANNEL_ERROR   (INTERNET_ERROR_BASE + 157)
#define ERROR_INTERNET_UNABLE_TO_CACHE_FILE     (INTERNET_ERROR_BASE + 158)
#define ERROR_INTERNET_TCPIP_NOT_INSTALLED      (INTERNET_ERROR_BASE + 159)
#define ERROR_INTERNET_DISCONNECTED             (INTERNET_ERROR_BASE + 163)
#define ERROR_INTERNET_SERVER_UNREACHABLE       (INTERNET_ERROR_BASE + 164)
#define ERROR_INTERNET_PROXY_SERVER_UNREACHABLE (INTERNET_ERROR_BASE + 165)
#define ERROR_INTERNET_BAD_AUTO_PROXY_SCRIPT    (INTERNET_ERROR_BASE + 166)
#define ERROR_INTERNET_UNABLE_TO_DOWNLOAD_SCRIPT (INTERNET_ERROR_BASE + 167)
#define ERROR_INTERNET_SEC_INVALID_CERT    (INTERNET_ERROR_BASE + 169)
#define ERROR_INTERNET_SEC_CERT_REVOKED    (INTERNET_ERROR_BASE + 170)
#define ERROR_INTERNET_FAILED_DUETOSECURITYCHECK  (INTERNET_ERROR_BASE + 171)
#define ERROR_INTERNET_NOT_INITIALIZED            (INTERNET_ERROR_BASE + 172)
#define ERROR_INTERNET_NEED_MSN_SSPI_PKG          (INTERNET_ERROR_BASE + 173)
#define ERROR_INTERNET_LOGIN_FAILURE_DISPLAY_ENTITY_BODY  (INTERNET_ERROR_BASE + 174)
#define ERROR_INTERNET_DECODING_FAILED            (INTERNET_ERROR_BASE + 175)
#define INTERNET_ERROR_LAST                       ERROR_INTERNET_DECODING_FAILED


#define NORMAL_CACHE_ENTRY              0x00000001
#define STICKY_CACHE_ENTRY              0x00000004
#define EDITED_CACHE_ENTRY              0x00000008
#define COOKIE_CACHE_ENTRY              0x00100000
#define URLHISTORY_CACHE_ENTRY          0x00200000
#define TRACK_OFFLINE_CACHE_ENTRY       0x00000010
#define TRACK_ONLINE_CACHE_ENTRY        0x00000020
#define SPARSE_CACHE_ENTRY              0x00010000

#define URLCACHE_FIND_DEFAULT_FILTER    NORMAL_CACHE_ENTRY             \
                                    |   COOKIE_CACHE_ENTRY             \
                                    |   URLHISTORY_CACHE_ENTRY         \
                                    |   TRACK_OFFLINE_CACHE_ENTRY      \
                                    |   TRACK_ONLINE_CACHE_ENTRY       \
                                    |   STICKY_CACHE_ENTRY


typedef struct _INTERNET_CACHE_ENTRY_INFOA {
    DWORD dwStructSize;
    LPSTR lpszSourceUrlName;
    LPSTR   lpszLocalFileName;
    DWORD CacheEntryType;
    DWORD dwUseCount;
    DWORD dwHitRate;
    DWORD dwSizeLow;
    DWORD dwSizeHigh;
    FILETIME LastModifiedTime;
    FILETIME ExpireTime;
    FILETIME LastAccessTime;
    FILETIME LastSyncTime;

    LPBYTE lpHeaderInfo;
    DWORD dwHeaderInfoSize;
    LPSTR lpszFileExtension;
    union {
      DWORD dwReserved;
      DWORD dwExemptDelta;
    } DUMMYUNIONNAME;
} INTERNET_CACHE_ENTRY_INFOA,* LPINTERNET_CACHE_ENTRY_INFOA;

typedef struct _INTERNET_CACHE_ENTRY_INFOW {
    DWORD dwStructSize;
    LPWSTR lpszSourceUrlName;
    LPWSTR  lpszLocalFileName;
    DWORD CacheEntryType;
    DWORD dwUseCount;
    DWORD dwHitRate;
    DWORD dwSizeLow;
    DWORD dwSizeHigh;
    FILETIME LastModifiedTime;
    FILETIME ExpireTime;
    FILETIME LastAccessTime;
    FILETIME LastSyncTime;

    LPBYTE lpHeaderInfo;
    DWORD dwHeaderInfoSize;
    LPWSTR  lpszFileExtension;
    union {
      DWORD dwReserved;
      DWORD dwExemptDelta;
    } DUMMYUNIONNAME;
} INTERNET_CACHE_ENTRY_INFOW,* LPINTERNET_CACHE_ENTRY_INFOW;

DECL_WINELIB_TYPE_AW(INTERNET_CACHE_ENTRY_INFO)
DECL_WINELIB_TYPE_AW(LPINTERNET_CACHE_ENTRY_INFO)

typedef struct _INTERNET_CACHE_TIMESTAMPS
{
    FILETIME ftExpires;
    FILETIME ftLastModified;
} INTERNET_CACHE_TIMESTAMPS, *LPINTERNET_CACHE_TIMESTAMPS;

BOOLAPI
CreateUrlCacheEntryA(
  _In_ LPCSTR lpszUrlName,
  _In_ DWORD dwExpectedFileSize,
  _In_opt_ LPCSTR lpszFileExtension,
  _Inout_updates_(MAX_PATH) LPSTR lpszFileName,
  _In_ DWORD dwReserved);

BOOLAPI
CreateUrlCacheEntryW(
  _In_ LPCWSTR lpszUrlName,
  _In_ DWORD dwExpectedFileSize,
  _In_opt_ LPCWSTR lpszFileExtension,
  _Inout_updates_(MAX_PATH) LPWSTR lpszFileName,
  _In_ DWORD dwReserved);

#define CreateUrlCacheEntry WINELIB_NAME_AW(CreateUrlCacheEntry)

BOOLAPI
CommitUrlCacheEntryA(
  _In_ LPCSTR lpszUrlName,
  _In_opt_ LPCSTR lpszLocalFileName,
  _In_ FILETIME ExpireTime,
  _In_ FILETIME LastModifiedTime,
  _In_ DWORD CacheEntryType,
  _In_reads_opt_(cchHeaderInfo) LPBYTE lpHeaderInfo,
  _In_ DWORD cchHeaderInfo,
  _Reserved_ LPCSTR lpszFileExtension,
  _In_opt_ LPCSTR lpszOriginalUrl);

BOOLAPI
CommitUrlCacheEntryW(
  _In_ LPCWSTR lpszUrlName,
  _In_opt_ LPCWSTR lpszLocalFileName,
  _In_ FILETIME ExpireTime,
  _In_ FILETIME LastModifiedTime,
  _In_ DWORD CacheEntryType,
  _In_reads_opt_(cchHeaderInfo) LPWSTR lpszHeaderInfo,
  _In_ DWORD cchHeaderInfo,
  _Reserved_ LPCWSTR lpszFileExtension,
  _In_opt_ LPCWSTR lpszOriginalUrl);

#define CommitUrlCacheEntry WINELIB_NAME_AW(CommitUrlCacheEntry)

BOOLAPI ResumeSuspendedDownload(_In_ HINTERNET, _In_ DWORD);

BOOLAPI
RetrieveUrlCacheEntryFileA(
  _In_ LPCSTR lpszUrlName,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo,
  _Inout_ LPDWORD lpcbCacheEntryInfo,
  _Reserved_ DWORD dwReserved);

BOOLAPI
RetrieveUrlCacheEntryFileW(
  _In_ LPCWSTR lpszUrlName,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo,
  _Inout_ LPDWORD lpcbCacheEntryInfo,
  _Reserved_ DWORD dwReserved);

#define RetrieveUrlCacheEntryFile WINELIB_NAME_AW(RetrieveUrlCacheEntryFile)

BOOLAPI UnlockUrlCacheEntryFileA(_In_ LPCSTR, _Reserved_ DWORD);
BOOLAPI UnlockUrlCacheEntryFileW(_In_ LPCWSTR, _Reserved_ DWORD);
#define UnlockUrlCacheEntryFile  WINELIB_NAME_AW(UnlockUrlCacheEntryFile)

INTERNETAPI
HANDLE
WINAPI
RetrieveUrlCacheEntryStreamA(
  _In_ LPCSTR  lpszUrlName,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo,
  _Inout_ LPDWORD lpcbCacheEntryInfo,
  _In_ BOOL fRandomRead,
  _Reserved_ DWORD dwReserved);

INTERNETAPI
HANDLE
WINAPI
RetrieveUrlCacheEntryStreamW(
  _In_ LPCWSTR  lpszUrlName,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo,
  _Inout_ LPDWORD lpcbCacheEntryInfo,
  _In_ BOOL fRandomRead,
  _Reserved_ DWORD dwReserved);

#define RetrieveUrlCacheEntryStream WINELIB_NAME_AW(RetrieveUrlCacheEntryStream)

BOOLAPI
ReadUrlCacheEntryStream(
  _In_ HANDLE hUrlCacheStream,
  _In_ DWORD dwLocation,
  _Out_writes_bytes_(*lpdwLen) __out_data_source(NETWORK) LPVOID lpBuffer,
  _Inout_ LPDWORD lpdwLen,
  _Reserved_ DWORD Reserved);

BOOLAPI UnlockUrlCacheEntryStream(_In_ HANDLE, _Reserved_ DWORD);

BOOLAPI
GetUrlCacheEntryInfoA(
  _In_ LPCSTR lpszUrlName,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo,
  _Inout_opt_ LPDWORD lpcbCacheEntryInfo);

BOOLAPI
GetUrlCacheEntryInfoW(
  _In_ LPCWSTR lpszUrlName,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo,
  _Inout_opt_ LPDWORD lpcbCacheEntryInfo);

#define GetUrlCacheEntryInfo WINELIB_NAME_AW(GetUrlCacheEntryInfo)

BOOLAPI
GetUrlCacheEntryInfoExA(
  _In_ LPCSTR lpszUrl,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOA lpCacheEntryInfo,
  _Inout_opt_ LPDWORD lpcbCacheEntryInfo,
  _Reserved_ LPSTR lpszRedirectUrl,
  _Reserved_ LPDWORD lpcbRedirectUrl,
  _Reserved_ LPVOID lpReserved,
  _In_ DWORD dwFlags);

BOOLAPI
GetUrlCacheEntryInfoExW(
  _In_ LPCWSTR lpszUrl,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOW lpCacheEntryInfo,
  _Inout_opt_ LPDWORD lpcbCacheEntryInfo,
  _Reserved_ LPWSTR lpszRedirectUrl,
  _Reserved_ LPDWORD lpcbRedirectUrl,
  _Reserved_ LPVOID lpReserved,
  _In_ DWORD dwFlags);

#define GetUrlCacheEntryInfoEx WINELIB_NAME_AW(GetUrlCacheEntryInfoEx)

#define CACHE_ENTRY_ATTRIBUTE_FC    0x00000004
#define CACHE_ENTRY_HITRATE_FC      0x00000010
#define CACHE_ENTRY_MODTIME_FC      0x00000040
#define CACHE_ENTRY_EXPTIME_FC      0x00000080
#define CACHE_ENTRY_ACCTIME_FC      0x00000100
#define CACHE_ENTRY_SYNCTIME_FC     0x00000200
#define CACHE_ENTRY_HEADERINFO_FC   0x00000400
#define CACHE_ENTRY_EXEMPT_DELTA_FC 0x00000800


BOOLAPI
SetUrlCacheEntryInfoA(
  _In_ LPCSTR,
  _In_ LPINTERNET_CACHE_ENTRY_INFOA,
  _In_ DWORD);

BOOLAPI
SetUrlCacheEntryInfoW(
  _In_ LPCWSTR,
  _In_ LPINTERNET_CACHE_ENTRY_INFOW,
  _In_ DWORD);

#define SetUrlCacheEntryInfo WINELIB_NAME_AW(SetUrlCacheEntryInfo)

typedef LONGLONG GROUPID;

INTERNETAPI GROUPID WINAPI CreateUrlCacheGroup(_In_ DWORD, _Reserved_ LPVOID);
BOOLAPI DeleteUrlCacheGroup(_In_ GROUPID, _In_ DWORD, _Reserved_ LPVOID);

INTERNETAPI
HANDLE
WINAPI
FindFirstUrlCacheGroup(
  _In_ DWORD,
  _In_ DWORD,
  _Reserved_ LPVOID,
  _Reserved_ DWORD,
  _Out_ GROUPID*,
  _Reserved_ LPVOID);

BOOLAPI FindNextUrlCacheGroup(_In_ HANDLE, _Out_ GROUPID*, _Reserved_ LPVOID);

BOOLAPI
GetUrlCacheGroupAttributeA(
  _In_ GROUPID gid,
  _Reserved_ DWORD dwFlags,
  _In_ DWORD dwAttributes,
  _Out_writes_bytes_(*lpcbGroupInfo) LPINTERNET_CACHE_GROUP_INFOA lpGroupInfo,
  _Inout_ LPDWORD lpcbGroupInfo,
  _Reserved_ LPVOID lpReserved);

BOOLAPI
GetUrlCacheGroupAttributeW(
  _In_ GROUPID gid,
  _Reserved_ DWORD dwFlags,
  _In_ DWORD dwAttributes,
  _Out_writes_bytes_(*lpcbGroupInfo) LPINTERNET_CACHE_GROUP_INFOW lpGroupInfo,
  _Inout_ LPDWORD lpcbGroupInfo,
  _Reserved_ LPVOID lpReserved);

#define GetUrlCacheGroupAttribute WINELIB_NAME_AW(GetUrlCacheGroupAttribute)

#define INTERNET_CACHE_GROUP_ADD      0
#define INTERNET_CACHE_GROUP_REMOVE   1

BOOLAPI
SetUrlCacheEntryGroupA(
  _In_ LPCSTR,
  _In_ DWORD,
  _In_ GROUPID,
  _Reserved_ LPBYTE,
  _Reserved_ DWORD,
  _Reserved_ LPVOID);

BOOLAPI
SetUrlCacheEntryGroupW(
  _In_ LPCWSTR,
  _In_ DWORD,
  _In_ GROUPID,
  _Reserved_ LPBYTE,
  _Reserved_ DWORD,
  _Reserved_ LPVOID);

#define SetUrlCacheEntryGroup WINELIB_NAME_AW(SetUrlCacheEntryGroup)

BOOLAPI
SetUrlCacheGroupAttributeA(
  _In_ GROUPID,
  _Reserved_ DWORD,
  _In_ DWORD,
  _In_ LPINTERNET_CACHE_GROUP_INFOA,
  _Reserved_ LPVOID);

BOOLAPI
SetUrlCacheGroupAttributeW(
  _In_ GROUPID,
  _Reserved_ DWORD,
  _In_ DWORD,
  _In_ LPINTERNET_CACHE_GROUP_INFOW,
  _Reserved_ LPVOID);

#define SetUrlCacheGroupAttribute WINELIB_NAME_AW(SetUrlCacheGroupAttribute)

INTERNETAPI
HANDLE
WINAPI
FindFirstUrlCacheEntryExA(
  _In_opt_ LPCSTR  lpszUrlSearchPattern,
  _In_ DWORD dwFlags,
  _In_ DWORD  dwFilter,
  _In_ GROUPID  GroupId,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOA lpFirstCacheEntryInfo,
  _Inout_ LPDWORD lpcbCacheEntryInfo,
  _Reserved_ LPVOID lpGroupAttributes,
  _Reserved_ LPDWORD lpcbGroupAttributes,
  _Reserved_ LPVOID lpReserved);

INTERNETAPI
HANDLE
WINAPI
FindFirstUrlCacheEntryExW(
  _In_opt_ LPCWSTR  lpszUrlSearchPattern,
  _In_ DWORD dwFlags,
  _In_ DWORD  dwFilter,
  _In_ GROUPID  GroupId,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOW lpFirstCacheEntryInfo,
  _Inout_ LPDWORD lpcbCacheEntryInfo,
  _Reserved_ LPVOID lpGroupAttributes,
  _Reserved_ LPDWORD lpcbGroupAttributes,
  _Reserved_ LPVOID lpReserved);

#define FindFirstUrlCacheEntryEx WINELIB_NAME_AW(FindFirstUrlCacheEntryEx)

BOOLAPI
FindNextUrlCacheEntryExA(
  _In_ HANDLE hEnumHandle,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOA lpNextCacheEntryInfo,
  _Inout_ LPDWORD lpcbCacheEntryInfo,
  _Reserved_ LPVOID lpGroupAttributes,
  _Reserved_ LPDWORD lpcbGroupAttributes,
  _Reserved_ LPVOID lpReserved);

BOOLAPI
FindNextUrlCacheEntryExW(
  _In_ HANDLE hEnumHandle,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOW lpNextCacheEntryInfo,
  _Inout_ LPDWORD lpcbCacheEntryInfo,
  _Reserved_ LPVOID lpGroupAttributes,
  _Reserved_ LPDWORD lpcbGroupAttributes,
  _Reserved_ LPVOID lpReserved);

#define FindNextUrlCacheEntryEx WINELIB_NAME_AW(FindNextUrlCacheEntryEx)

INTERNETAPI
HANDLE
WINAPI
FindFirstUrlCacheEntryA(
  _In_opt_ LPCSTR lpszUrlSearchPattern,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOA lpFirstCacheEntryInfo,
  _Inout_ LPDWORD lpcbCacheEntryInfo);

INTERNETAPI
HANDLE
WINAPI
FindFirstUrlCacheEntryW(
  _In_opt_ LPCWSTR lpszUrlSearchPattern,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOW lpFirstCacheEntryInfo,
  _Inout_ LPDWORD lpcbCacheEntryInfo);

#define FindFirstUrlCacheEntry WINELIB_NAME_AW(FindFirstUrlCacheEntry)

BOOLAPI
FindNextUrlCacheEntryA(
  _In_ HANDLE hEnumHandle,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOA lpNextCacheEntryInfo,
  _Inout_ LPDWORD lpcbCacheEntryInfo);

BOOLAPI
FindNextUrlCacheEntryW(
  _In_ HANDLE hEnumHandle,
  _Inout_updates_bytes_opt_(*lpcbCacheEntryInfo) LPINTERNET_CACHE_ENTRY_INFOW lpNextCacheEntryInfo,
  _Inout_ LPDWORD lpcbCacheEntryInfo);

#define FindNextUrlCacheEntry WINELIB_NAME_AW(FindNextUrlCacheEntry)

BOOLAPI FindCloseUrlCache(_In_ HANDLE);

BOOLAPI DeleteUrlCacheEntryA(_In_ LPCSTR);
BOOLAPI DeleteUrlCacheEntryW(_In_ LPCWSTR);
#define DeleteUrlCacheEntry  WINELIB_NAME_AW(DeleteUrlCacheEntry)

/* FCS_ flags and FreeUrlCacheSpace are no longer documented */
#define FCS_PERCENT_CACHE_SPACE  0  /* guessed value */
#define FCS_PERCENT_DISK_SPACE   1  /* guessed value */
#define FCS_ABSOLUTE_SIZE        2  /* guessed value */

BOOLAPI FreeUrlCacheSpaceA(LPCSTR ,DWORD ,DWORD);
BOOLAPI FreeUrlCacheSpaceW(LPCWSTR ,DWORD ,DWORD);
#define FreeUrlCacheSpace  WINELIB_NAME_AW(FreeUrlCacheSpace)

INTERNETAPI
DWORD
WINAPI
InternetDialA(
  _In_ HWND,
  _In_opt_ LPSTR,
  _In_ DWORD,
  _Out_ DWORD_PTR*,
  _Reserved_ DWORD);

INTERNETAPI
DWORD
WINAPI
InternetDialW(
  _In_ HWND,
  _In_opt_ LPWSTR,
  _In_ DWORD,
  _Out_ DWORD_PTR*,
  _Reserved_ DWORD);

#define InternetDial WINELIB_NAME_AW(InternetDial)

#define INTERNET_DIAL_UNATTENDED       0x8000

INTERNETAPI DWORD WINAPI InternetHangUp(_In_ DWORD_PTR, _Reserved_ DWORD);
BOOLAPI CreateMD5SSOHash(_In_ PWSTR, _In_ PWSTR, _In_ PWSTR, _Out_ PBYTE);

#define INTERENT_GOONLINE_REFRESH 0x00000001
#define INTERENT_GOONLINE_MASK 0x00000001

BOOLAPI InternetGoOnlineA(_In_opt_ LPSTR, _In_ HWND, _In_ DWORD);
BOOLAPI InternetGoOnlineW(_In_opt_ LPWSTR, _In_ HWND, _In_ DWORD);
#define InternetGoOnline  WINELIB_NAME_AW(InternetGoOnline)

BOOLAPI InternetAutodial(_In_ DWORD, _In_opt_ HWND);

#define INTERNET_AUTODIAL_FORCE_ONLINE          1
#define INTERNET_AUTODIAL_FORCE_UNATTENDED      2
#define INTERNET_AUTODIAL_FAILIFSECURITYCHECK   4

#define INTERNET_AUTODIAL_FLAGS_MASK (INTERNET_AUTODIAL_FORCE_ONLINE | INTERNET_AUTODIAL_FORCE_UNATTENDED | INTERNET_AUTODIAL_FAILIFSECURITYCHECK)

BOOL WINAPI InternetAutodialHangup(_Reserved_ DWORD);
BOOL WINAPI InternetGetConnectedState(_Out_ LPDWORD, _Reserved_ DWORD);

#define INTERNET_CONNECTION_MODEM        0x01
#define INTERNET_CONNECTION_LAN          0x02
#define INTERNET_CONNECTION_PROXY        0x04
#define INTERNET_CONNECTION_MODEM_BUSY   0x08
#define INTERNET_RAS_INSTALLED           0x10
#define INTERNET_CONNECTION_OFFLINE      0x20
#define INTERNET_CONNECTION_CONFIGURED   0x40

typedef DWORD (CALLBACK *PFN_DIAL_HANDLER) (HWND,LPCSTR,DWORD,LPDWORD);

#define INTERNET_CUSTOMDIAL_CONNECT         0
#define INTERNET_CUSTOMDIAL_UNATTENDED      1
#define INTERNET_CUSTOMDIAL_DISCONNECT      2
#define INTERNET_CUSTOMDIAL_SHOWOFFLINE     4
#define INTERNET_CUSTOMDIAL_SAFE_FOR_UNATTENDED 1
#define INTERNET_CUSTOMDIAL_WILL_SUPPLY_STATE   2
#define INTERNET_CUSTOMDIAL_CAN_HANGUP          4

BOOLAPI InternetSetDialStateA(_In_opt_ LPCSTR, _In_ DWORD, _Reserved_ DWORD);
BOOLAPI InternetSetDialStateW(_In_opt_ LPCWSTR, _In_ DWORD, _Reserved_ DWORD);
#define InternetSetDialState WINELIB_NAME_AW(InternetSetDialState)

#define INTERNET_DIALSTATE_DISCONNECTED     1

BOOLAPI
InternetGetConnectedStateExA(
  _Out_opt_ LPDWORD lpdwFlags,
  _Out_writes_opt_(cchNameLen) LPSTR lpszConnectionName,
  _In_ DWORD cchNameLen,
  _Reserved_ DWORD dwReserved);

BOOLAPI
InternetGetConnectedStateExW(
  _Out_opt_ LPDWORD lpdwFlags,
  _Out_writes_opt_(cchNameLen) LPWSTR lpszConnectionName,
  _In_ DWORD cchNameLen,
  _Reserved_ DWORD dwReserved);

#define InternetGetConnectedStateEx WINELIB_NAME_AW(InternetGetConnectedStateEx)

typedef struct AutoProxyHelperVtbl
{
    BOOL  (WINAPI *IsResolvable)(LPSTR);
    DWORD (WINAPI *GetIPAddress)(LPSTR, LPDWORD);
    DWORD (WINAPI *ResolveHostName)(LPSTR, LPSTR, LPDWORD);
    BOOL  (WINAPI *IsInNet)(LPSTR, LPSTR, LPSTR);
    BOOL  (WINAPI *IsResolvableEx)(LPSTR);
    DWORD (WINAPI *GetIPAddressEx)(LPSTR, LPDWORD);
    DWORD (WINAPI *ResolveHostNameEx)(LPSTR, LPSTR, LPDWORD);
    BOOL  (WINAPI *IsInNetEx)(LPSTR, LPSTR);
    DWORD (WINAPI *SortIpList)(LPSTR, LPSTR, LPDWORD);
} AutoProxyHelperVtbl;

typedef struct AutoProxyHelperFunctions
{
    const struct AutoProxyHelperVtbl *lpVtbl;
} AutoProxyHelperFunctions;

typedef struct
{
    DWORD dwStructSize;
    LPSTR lpszScriptBuffer;
    DWORD dwScriptBufferSize;
} AUTO_PROXY_SCRIPT_BUFFER, *LPAUTO_PROXY_SCRIPT_BUFFER;

BOOLAPI InternetInitializeAutoProxyDll(_In_ DWORD);

BOOLAPI
DetectAutoProxyUrl(
  _Out_writes_(cchAutoProxyUrl) PSTR pszAutoProxyUrl,
  _In_ DWORD cchAutoProxyUrl,
  _In_ DWORD dwDetectFlags);

#ifdef __cplusplus
}
#endif

#endif /* _WINE_WININET_H_ */

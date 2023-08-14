/*
 * syssetup.h
 *
 * System setup API, native interface
 *
 * This file is part of the ReactOS Operating System.
 *
 * Contributors:
 *  Created by Eric Kohl
 *
 *  THIS SOFTWARE IS NOT COPYRIGHTED
 *
 *  This source code is offered for use in the public domain. You may
 *  use, modify or distribute it freely.
 *
 *  This code is distributed in the hope that it will be useful but
 *  WITHOUT ANY WARRANTY. ALL WARRANTIES, EXPRESS OR IMPLIED ARE HEREBY
 *  DISCLAMED. This includes but is not limited to warranties of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __SYSSETUP_H_INCLUDED__
#define __SYSSETUP_H_INCLUDED__

typedef enum _PRODUCT_OPTION
{
    PRODUCT_OPTION_SERVER,
    PRODUCT_OPTION_WORKSTATION,
    PRODUCT_OPTION_DEFAULT = PRODUCT_OPTION_SERVER
} PRODUCT_OPTION, *PPRODUCT_OPTION;

/* Private Setup data shared between syssetup.dll and netshell.dll */
typedef struct _SETUPDATA
{
    HFONT hTitleFont;
    HFONT hBoldFont;

    WCHAR SourcePath[MAX_PATH];   // PCWSTR
    WCHAR UnattendFile[MAX_PATH]; // PCWSTR

    WCHAR OwnerName[51];
    WCHAR OwnerOrganization[51];
    WCHAR ComputerName[MAX_COMPUTERNAME_LENGTH + 1];  /* max. 15 characters */
    WCHAR AdminPassword[128];                         /* max. 127 characters */
    BOOL  UnattendSetup;
    BOOL  DisableGeckoInst;

    SYSTEMTIME SystemTime;
    struct _TIMEZONE_ENTRY* TimeZoneListHead;
    struct _TIMEZONE_ENTRY* TimeZoneListTail;
    DWORD TimeZoneIndex;
    DWORD DisableAutoDaylightTimeSet;
    LCID LocaleID;

    HINF hSetupInf;

    UINT uFirstNetworkWizardPage;
    UINT uPostNetworkWizardPage;

    PRODUCT_OPTION ProductOption;
} SETUPDATA, *PSETUPDATA;


/* System setup APIs */

NTSTATUS
WINAPI
SetAccountsDomainSid(
    PSID DomainSid,
    LPCWSTR DomainName);

/* Log File APIs */

BOOL WINAPI
InitializeSetupActionLog(IN BOOL bDeleteOldLogFile);

VOID WINAPI
TerminateSetupActionLog(VOID);

VOID
CDECL
pSetupDebugPrint(
    IN PCWSTR pszFileName,
    IN INT nLineNumber,
    IN PCWSTR pszTag,
    IN PCWSTR pszMessage,
    ...);

#define __WFILE__ TOWL1(__FILE__)
#define TOWL1(p) TOWL2(p)
#define TOWL2(p) L##p

#if defined(_MSC_VER)
#define LogItem(lpTag, lpMessageText, ...) \
    pSetupDebugPrint(__WFILE__, __LINE__, lpTag, lpMessageText, __VA_ARGS__)
#else
#define LogItem(lpTag, lpMessageText...) \
    pSetupDebugPrint(__WFILE__, __LINE__, lpTag, lpMessageText)
#endif

#endif /* __SYSSETUP_H_INCLUDED__ */

/* EOF */

/*
 * PROJECT:     ReactOS headers
 * LICENSE:     LGPL-2.0-or-later (https://spdx.org/licenses/LGPL-2.0-or-later)
 * PURPOSE:     Providing DDK-compatible <immdev.h> and IME/IMM development helper
 * COPYRIGHT:   Copyright 2021-2022 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>
 */

#ifndef _IMMDEV_
#define _IMMDEV_

#pragma once

#include <wingdi.h>
#include <imm.h>

#ifdef __cplusplus
extern "C" {
#endif

/* wParam for WM_IME_CONTROL */
#define IMC_GETCONVERSIONMODE           0x0001
#define IMC_GETSENTENCEMODE             0x0003
#define IMC_GETOPENSTATUS               0x0005
#define IMC_GETSOFTKBDPOS               0x0013
#define IMC_SETSOFTKBDPOS               0x0014

/* wParam for WM_IME_SYSTEM */
#define IMS_NOTIFYIMESHOW       0x05
#define IMS_UPDATEIMEUI         0x06
#define IMS_SETCANDFORM         0x09
#define IMS_SETCOMPFONT         0x0A
#define IMS_SETCOMPFORM         0x0B
#define IMS_CONFIGURE           0x0D
#define IMS_SETOPENSTATUS       0x0F
#define IMS_FREELAYOUT          0x11
#define IMS_GETCONVSTATUS       0x14
#define IMS_IMEHELP             0x15
#define IMS_IMEACTIVATE         0x17
#define IMS_IMEDEACTIVATE       0x18
#define IMS_ACTIVATELAYOUT      0x19
#define IMS_GETIMEMENU          0x1C
#define IMS_GETCONTEXT          0x1E
#define IMS_SENDNOTIFICATION    0x1F
#define IMS_COMPLETECOMPSTR     0x20
#define IMS_LOADTHREADLAYOUT    0x21
#define IMS_SETLANGBAND         0x23
#define IMS_UNSETLANGBAND       0x24

#define IMMGWL_IMC       0
#define IMMGWL_PRIVATE   (sizeof(LONG))

#define IMMGWLP_IMC      0
#define IMMGWLP_PRIVATE  (sizeof(LONG_PTR))

typedef struct _tagINPUTCONTEXT {
    HWND                hWnd;
    BOOL                fOpen;
    POINT               ptStatusWndPos;
    POINT               ptSoftKbdPos;
    DWORD               fdwConversion;
    DWORD               fdwSentence;
    union   {
        LOGFONTA        A;
        LOGFONTW        W;
    } lfFont;
    COMPOSITIONFORM     cfCompForm;
    CANDIDATEFORM       cfCandForm[4];
    HIMCC               hCompStr;
    HIMCC               hCandInfo;
    HIMCC               hGuideLine;
    HIMCC               hPrivate;
    DWORD               dwNumMsgBuf;
    HIMCC               hMsgBuf;
    DWORD               fdwInit;
    DWORD               dwReserve[3];
} INPUTCONTEXT, *PINPUTCONTEXT, *LPINPUTCONTEXT;

#ifdef _WIN64
C_ASSERT(offsetof(INPUTCONTEXT, hWnd) == 0x0);
C_ASSERT(offsetof(INPUTCONTEXT, fOpen) == 0x8);
C_ASSERT(offsetof(INPUTCONTEXT, ptStatusWndPos) == 0xc);
C_ASSERT(offsetof(INPUTCONTEXT, ptSoftKbdPos) == 0x14);
C_ASSERT(offsetof(INPUTCONTEXT, fdwConversion) == 0x1c);
C_ASSERT(offsetof(INPUTCONTEXT, fdwSentence) == 0x20);
C_ASSERT(offsetof(INPUTCONTEXT, lfFont) == 0x24);
C_ASSERT(offsetof(INPUTCONTEXT, cfCompForm) == 0x80);
C_ASSERT(offsetof(INPUTCONTEXT, cfCandForm) == 0x9c);
C_ASSERT(offsetof(INPUTCONTEXT, hCompStr) == 0x120);
C_ASSERT(offsetof(INPUTCONTEXT, hCandInfo) == 0x128);
C_ASSERT(offsetof(INPUTCONTEXT, hGuideLine) == 0x130);
C_ASSERT(offsetof(INPUTCONTEXT, hPrivate) == 0x138);
C_ASSERT(offsetof(INPUTCONTEXT, dwNumMsgBuf) == 0x140);
C_ASSERT(offsetof(INPUTCONTEXT, hMsgBuf) == 0x148);
C_ASSERT(offsetof(INPUTCONTEXT, fdwInit) == 0x150);
C_ASSERT(offsetof(INPUTCONTEXT, dwReserve) == 0x154);
C_ASSERT(sizeof(INPUTCONTEXT) == 0x160);
#else
C_ASSERT(offsetof(INPUTCONTEXT, hWnd) == 0x0);
C_ASSERT(offsetof(INPUTCONTEXT, fOpen) == 0x4);
C_ASSERT(offsetof(INPUTCONTEXT, ptStatusWndPos) == 0x8);
C_ASSERT(offsetof(INPUTCONTEXT, ptSoftKbdPos) == 0x10);
C_ASSERT(offsetof(INPUTCONTEXT, fdwConversion) == 0x18);
C_ASSERT(offsetof(INPUTCONTEXT, fdwSentence) == 0x1c);
C_ASSERT(offsetof(INPUTCONTEXT, lfFont) == 0x20);
C_ASSERT(offsetof(INPUTCONTEXT, cfCompForm) == 0x7c);
C_ASSERT(offsetof(INPUTCONTEXT, cfCandForm) == 0x98);
C_ASSERT(offsetof(INPUTCONTEXT, hCompStr) == 0x118);
C_ASSERT(offsetof(INPUTCONTEXT, hCandInfo) == 0x11c);
C_ASSERT(offsetof(INPUTCONTEXT, hGuideLine) == 0x120);
C_ASSERT(offsetof(INPUTCONTEXT, hPrivate) == 0x124);
C_ASSERT(offsetof(INPUTCONTEXT, dwNumMsgBuf) == 0x128);
C_ASSERT(offsetof(INPUTCONTEXT, hMsgBuf) == 0x12c);
C_ASSERT(offsetof(INPUTCONTEXT, fdwInit) == 0x130);
C_ASSERT(offsetof(INPUTCONTEXT, dwReserve) == 0x134);
C_ASSERT(sizeof(INPUTCONTEXT) == 0x140);
#endif

struct IME_STATE;

/* unconfirmed */
#ifdef __cplusplus
typedef struct INPUTCONTEXTDX : INPUTCONTEXT
{
#else
typedef struct INPUTCONTEXTDX
{
    INPUTCONTEXT;
#endif
    UINT nVKey;
    BOOL bNeedsTrans;
    DWORD dwUnknown1;
    DWORD dwUIFlags;
    DWORD dwUnknown2;
    struct IME_STATE *pState;
    DWORD dwChange;
    DWORD dwUnknown5;
} INPUTCONTEXTDX, *PINPUTCONTEXTDX, *LPINPUTCONTEXTDX;

#ifndef _WIN64
C_ASSERT(offsetof(INPUTCONTEXTDX, nVKey) == 0x140);
C_ASSERT(offsetof(INPUTCONTEXTDX, bNeedsTrans) == 0x144);
C_ASSERT(offsetof(INPUTCONTEXTDX, dwUIFlags) == 0x14c);
C_ASSERT(offsetof(INPUTCONTEXTDX, pState) == 0x154);
C_ASSERT(offsetof(INPUTCONTEXTDX, dwChange) == 0x158);
C_ASSERT(sizeof(INPUTCONTEXTDX) == 0x160);
#endif

// bits of fdwInit of INPUTCONTEXT
#define INIT_STATUSWNDPOS               0x00000001
#define INIT_CONVERSION                 0x00000002
#define INIT_SENTENCE                   0x00000004
#define INIT_LOGFONT                    0x00000008
#define INIT_COMPFORM                   0x00000010
#define INIT_SOFTKBDPOS                 0x00000020

// bits for INPUTCONTEXTDX.dwChange
#define INPUTCONTEXTDX_CHANGE_OPEN          0x1
#define INPUTCONTEXTDX_CHANGE_CONVERSION    0x2
#define INPUTCONTEXTDX_CHANGE_SENTENCE      0x4
#define INPUTCONTEXTDX_CHANGE_FORCE_OPEN    0x100

#ifndef WM_IME_REPORT
    #define WM_IME_REPORT 0x280
#endif

// WM_IME_REPORT wParam
#define IR_STRINGSTART   0x100
#define IR_STRINGEND     0x101
#define IR_OPENCONVERT   0x120
#define IR_CHANGECONVERT 0x121
#define IR_CLOSECONVERT  0x122
#define IR_FULLCONVERT   0x123
#define IR_IMESELECT     0x130
#define IR_STRING        0x140
#define IR_DBCSCHAR      0x160
#define IR_UNDETERMINE   0x170
#define IR_STRINGEX      0x180
#define IR_MODEINFO      0x190

// for IR_UNDETERMINE
typedef struct tagUNDETERMINESTRUCT
{
    DWORD dwSize;
    UINT  uDefIMESize;
    UINT  uDefIMEPos;
    UINT  uUndetTextLen;
    UINT  uUndetTextPos;
    UINT  uUndetAttrPos;
    UINT  uCursorPos;
    UINT  uDeltaStart;
    UINT  uDetermineTextLen;
    UINT  uDetermineTextPos;
    UINT  uDetermineDelimPos;
    UINT  uYomiTextLen;
    UINT  uYomiTextPos;
    UINT  uYomiDelimPos;
} UNDETERMINESTRUCT, *PUNDETERMINESTRUCT, *LPUNDETERMINESTRUCT;

LPINPUTCONTEXT WINAPI ImmLockIMC(HIMC);

typedef struct IME_SUBSTATE
{
    struct IME_SUBSTATE *pNext;
    HKL hKL;
    DWORD dwValue;
} IME_SUBSTATE, *PIME_SUBSTATE;

#ifndef _WIN64
C_ASSERT(sizeof(IME_SUBSTATE) == 0xc);
#endif

typedef struct IME_STATE
{
    struct IME_STATE *pNext;
    WORD wLang;
    WORD fOpen;
    DWORD dwConversion;
    DWORD dwSentence;
    DWORD dwInit;
    PIME_SUBSTATE pSubState;
} IME_STATE, *PIME_STATE;

#ifndef _WIN64
C_ASSERT(sizeof(IME_STATE) == 0x18);
#endif

#ifdef __cplusplus
} // extern "C"
#endif

#endif  /* ndef _IMMDEV_ */

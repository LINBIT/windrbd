/*
 * ReactOS shlwapi
 *
 * Copyright 2009 Andrew Hill <ash77 at domain reactos.org>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __SHLWAPI_UNDOC_H
#define __SHLWAPI_UNDOC_H

#ifdef __cplusplus
extern "C" {
#endif /* defined(__cplusplus) */

BOOL WINAPI SHAboutInfoA(LPSTR lpszDest, DWORD dwDestLen);
BOOL WINAPI SHAboutInfoW(LPWSTR lpszDest, DWORD dwDestLen);
#ifdef UNICODE
#define SHAboutInfo SHAboutInfoW
#else
#define SHAboutInfo SHAboutInfoA
#endif

HMODULE WINAPI SHPinDllOfCLSID(REFIID refiid);
HRESULT WINAPI IUnknown_QueryStatus(IUnknown *lpUnknown, REFGUID pguidCmdGroup, ULONG cCmds, OLECMD *prgCmds, OLECMDTEXT* pCmdText);
HRESULT WINAPI IUnknown_Exec(IUnknown* lpUnknown, REFGUID pguidCmdGroup, DWORD nCmdID, DWORD nCmdexecopt, VARIANT* pvaIn, VARIANT* pvaOut);
LONG WINAPI SHSetWindowBits(HWND hwnd, INT offset, UINT wMask, UINT wFlags);
HWND WINAPI SHSetParentHwnd(HWND hWnd, HWND hWndParent);
HRESULT WINAPI ConnectToConnectionPoint(IUnknown *lpUnkSink, REFIID riid, BOOL bAdviseOnly, IUnknown *lpUnknown, LPDWORD lpCookie, IConnectionPoint **lppCP);
BOOL WINAPI SHIsSameObject(IUnknown *lpInt1, IUnknown *lpInt2);
BOOL WINAPI SHLoadMenuPopup(HINSTANCE hInst, LPCWSTR szName);
void WINAPI SHPropagateMessage(HWND hWnd, UINT uiMsgId, WPARAM wParam, LPARAM lParam, BOOL bSend);
DWORD WINAPI SHRemoveAllSubMenus(HMENU hMenu);
UINT WINAPI SHEnableMenuItem(HMENU hMenu, UINT wItemID, BOOL bEnable);
DWORD WINAPI SHCheckMenuItem(HMENU hMenu, UINT uID, BOOL bCheck);
DWORD WINAPI SHRegisterClassA(WNDCLASSA *wndclass);
BOOL WINAPI SHSimulateDrop(IDropTarget *pDrop, IDataObject *pDataObj, DWORD grfKeyState, PPOINTL lpPt, DWORD* pdwEffect);
HMENU WINAPI SHGetMenuFromID(HMENU hMenu, UINT uID);
DWORD WINAPI SHGetCurColorRes(void);
DWORD WINAPI SHWaitForSendMessageThread(HANDLE hand, DWORD dwTimeout);
HRESULT WINAPI SHIsExpandableFolder(LPSHELLFOLDER lpFolder, LPCITEMIDLIST pidl);
DWORD WINAPI SHFillRectClr(HDC hDC, LPCRECT pRect, COLORREF cRef);
int WINAPI SHSearchMapInt(const int *lpKeys, const int *lpValues, int iLen, int iKey);
VOID WINAPI IUnknown_Set(IUnknown **lppDest, IUnknown *lpUnknown);
HRESULT WINAPI MayQSForward(IUnknown* lpUnknown, PVOID lpReserved, REFGUID riidCmdGrp, ULONG cCmds, OLECMD *prgCmds, OLECMDTEXT *pCmdText);
HRESULT WINAPI MayExecForward(IUnknown* lpUnknown, INT iUnk, REFGUID pguidCmdGroup, DWORD nCmdID, DWORD nCmdexecopt, VARIANT *pvaIn, VARIANT *pvaOut);
HRESULT WINAPI IsQSForward(REFGUID pguidCmdGroup,ULONG cCmds, OLECMD *prgCmds);
BOOL WINAPI SHIsChildOrSelf(HWND hParent, HWND hChild);
HRESULT WINAPI SHForwardContextMenuMsg(IUnknown* pUnk, UINT uMsg, WPARAM wParam, LPARAM lParam, LRESULT* pResult, BOOL useIContextMenu2);

HRESULT WINAPI SHRegGetCLSIDKeyW(REFGUID guid, LPCWSTR lpszValue, BOOL bUseHKCU, BOOL bCreate, PHKEY phKey);

BOOL WINAPI SHAddDataBlock(LPDBLIST* lppList, const DATABLOCK_HEADER *lpNewItem);
BOOL WINAPI SHRemoveDataBlock(LPDBLIST* lppList, DWORD dwSignature);
DATABLOCK_HEADER* WINAPI SHFindDataBlock(LPDBLIST lpList, DWORD dwSignature);
HRESULT WINAPI SHWriteDataBlockList(IStream* lpStream, LPDBLIST lpList);
HRESULT WINAPI SHReadDataBlockList(IStream* lpStream, LPDBLIST* lppList);
VOID WINAPI SHFreeDataBlockList(LPDBLIST lpList);

/* Redirected to kernel32.ExpandEnvironmentStringsA/W */
DWORD WINAPI SHExpandEnvironmentStringsA(LPCSTR,LPSTR,DWORD);
DWORD WINAPI SHExpandEnvironmentStringsW(LPCWSTR,LPWSTR,DWORD);
#ifdef UNICODE
#define SHExpandEnvironmentStrings SHExpandEnvironmentStringsW
#else
#define SHExpandEnvironmentStrings SHExpandEnvironmentStringsA
#endif

/* Redirected to userenv.ExpandEnvironmentStringsForUserA/W */
#if (WINVER >= 0x0500)
BOOL WINAPI SHExpandEnvironmentStringsForUserA(HANDLE, LPCSTR, LPSTR, DWORD);
BOOL WINAPI SHExpandEnvironmentStringsForUserW(HANDLE, LPCWSTR, LPWSTR, DWORD);
#ifdef UNICODE
#define SHExpandEnvironmentStringsForUser SHExpandEnvironmentStringsForUserW
#else
#define SHExpandEnvironmentStringsForUser SHExpandEnvironmentStringsForUserA
#endif
#endif


BOOL WINAPI SHIsEmptyStream(IStream*);
HRESULT WINAPI IStream_Size(IStream *lpStream, ULARGE_INTEGER* lpulSize);
HRESULT WINAPI SHInvokeDefaultCommand(HWND,IShellFolder*,LPCITEMIDLIST);
HRESULT WINAPI SHPropertyBag_ReadType(IPropertyBag *ppb, LPCWSTR pszPropName, VARIANTARG *pvarg, VARTYPE vt);
HRESULT WINAPI SHPropertyBag_ReadBOOL(IPropertyBag *ppb, LPCWSTR pszPropName, BOOL *pbValue);
BOOL WINAPI SHPropertyBag_ReadBOOLOld(IPropertyBag *ppb, LPCWSTR pszPropName, BOOL bDefValue);
HRESULT WINAPI SHPropertyBag_ReadSHORT(IPropertyBag *ppb, LPCWSTR pszPropName, SHORT *psValue);
HRESULT WINAPI SHPropertyBag_ReadInt(IPropertyBag *ppb, LPCWSTR pszPropName, LPINT pnValue);
HRESULT WINAPI SHPropertyBag_ReadLONG(IPropertyBag *ppb, LPCWSTR pszPropName, LPLONG pValue);
HRESULT WINAPI SHPropertyBag_ReadDWORD(IPropertyBag *ppb, LPCWSTR pszPropName, DWORD *pdwValue);
HRESULT WINAPI SHPropertyBag_ReadBSTR(IPropertyBag *ppb, LPCWSTR pszPropName, BSTR *pbstr);
HRESULT WINAPI SHPropertyBag_ReadStr(IPropertyBag *ppb, LPCWSTR pszPropName, LPWSTR pszDst, int cchMax);
HRESULT WINAPI SHPropertyBag_ReadPOINTL(IPropertyBag *ppb, LPCWSTR pszPropName, POINTL *pptl);
HRESULT WINAPI SHPropertyBag_ReadPOINTS(IPropertyBag *ppb, LPCWSTR pszPropName, POINTS *ppts);
HRESULT WINAPI SHPropertyBag_ReadRECTL(IPropertyBag *ppb, LPCWSTR pszPropName, RECTL *prcl);
HRESULT WINAPI SHPropertyBag_ReadGUID(IPropertyBag *ppb, LPCWSTR pszPropName, GUID *pguid);
HRESULT WINAPI SHPropertyBag_ReadStream(IPropertyBag *ppb, LPCWSTR pszPropName, IStream **ppStream);

HRESULT WINAPI SHGetPerScreenResName(OUT LPWSTR lpResName,
                                     IN INT cchResName,
                                     IN DWORD dwReserved);

HRESULT WINAPI SHPropertyBag_Delete(IPropertyBag *ppb, LPCWSTR pszPropName);
HRESULT WINAPI SHPropertyBag_WriteBOOL(IPropertyBag *ppb, LPCWSTR pszPropName, BOOL bValue);
HRESULT WINAPI SHPropertyBag_WriteSHORT(IPropertyBag *ppb, LPCWSTR pszPropName, SHORT sValue);
HRESULT WINAPI SHPropertyBag_WriteInt(IPropertyBag *ppb, LPCWSTR pszPropName, INT nValue);
HRESULT WINAPI SHPropertyBag_WriteLONG(IPropertyBag *ppb, LPCWSTR pszPropName, LONG lValue);
HRESULT WINAPI SHPropertyBag_WriteDWORD(IPropertyBag *ppb, LPCWSTR pszPropName, DWORD dwValue);
HRESULT WINAPI SHPropertyBag_WriteStr(IPropertyBag *ppb, LPCWSTR pszPropName, LPCWSTR pszValue);
HRESULT WINAPI SHPropertyBag_WriteGUID(IPropertyBag *ppb, LPCWSTR pszPropName, const GUID *pguid);
HRESULT WINAPI SHPropertyBag_WriteStream(IPropertyBag *ppb, LPCWSTR pszPropName, IStream *pStream);
HRESULT WINAPI SHPropertyBag_WritePOINTL(IPropertyBag *ppb, LPCWSTR pszPropName, const POINTL *pptl);
HRESULT WINAPI SHPropertyBag_WritePOINTS(IPropertyBag *ppb, LPCWSTR pszPropName, const POINTS *ppts);
HRESULT WINAPI SHPropertyBag_WriteRECTL(IPropertyBag *ppb, LPCWSTR pszPropName, const RECTL *prcl);

HRESULT WINAPI SHCreatePropertyBagOnMemory(_In_ DWORD dwMode, _In_ REFIID riid, _Out_ void **ppvObj);

HRESULT WINAPI
SHCreatePropertyBagOnRegKey(
    _In_ HKEY hKey,
    _In_z_ LPCWSTR pszSubKey,
    _In_ DWORD dwMode,
    _In_ REFIID riid,
    _Out_ void **ppvObj);

HWND WINAPI SHCreateWorkerWindowA(WNDPROC wndProc, HWND hWndParent, DWORD dwExStyle,
                                  DWORD dwStyle, HMENU hMenu, LONG_PTR wnd_extra);

HWND WINAPI SHCreateWorkerWindowW(WNDPROC wndProc, HWND hWndParent, DWORD dwExStyle,
                                  DWORD dwStyle, HMENU hMenu, LONG_PTR wnd_extra);
#ifdef UNICODE
#define SHCreateWorkerWindow SHCreateWorkerWindowW
#else
#define SHCreateWorkerWindow SHCreateWorkerWindowA
#endif

HRESULT WINAPI IUnknown_SetOwner(IUnknown *iface, IUnknown *pUnk);
HRESULT WINAPI IUnknown_GetClassID(IUnknown *lpUnknown, CLSID *lpClassId);
HRESULT WINAPI IUnknown_QueryServiceExec(IUnknown *lpUnknown, REFIID service, const GUID *group, DWORD cmdId, DWORD cmdOpt, VARIANT *pIn, VARIANT *pOut);
HRESULT WINAPI IUnknown_UIActivateIO(IUnknown *unknown, BOOL activate, LPMSG msg);
HRESULT WINAPI IUnknown_TranslateAcceleratorOCS(IUnknown *lpUnknown, LPMSG lpMsg, DWORD dwModifiers);
HRESULT WINAPI IUnknown_OnFocusOCS(IUnknown *lpUnknown, BOOL fGotFocus);
HRESULT WINAPI IUnknown_HandleIRestrict(LPUNKNOWN lpUnknown, PVOID lpArg1, PVOID lpArg2, PVOID lpArg3, PVOID lpArg4);
HRESULT WINAPI IUnknown_HasFocusIO(IUnknown * punk);
HRESULT WINAPI IUnknown_TranslateAcceleratorIO(IUnknown * punk, MSG * pmsg);
HRESULT WINAPI IUnknown_OnFocusChangeIS(LPUNKNOWN lpUnknown, LPUNKNOWN pFocusObject, BOOL bFocus);

DWORD WINAPI SHAnsiToUnicode(LPCSTR lpSrcStr, LPWSTR lpDstStr, INT iLen);
INT WINAPI SHUnicodeToAnsi(LPCWSTR lpSrcStr, LPSTR lpDstStr, INT iLen);

DWORD WINAPI SHAnsiToUnicodeCP(DWORD dwCp, LPCSTR lpSrcStr, LPWSTR lpDstStr, int iLen);
DWORD WINAPI SHUnicodeToAnsiCP(UINT CodePage, LPCWSTR lpSrcStr, LPSTR lpDstStr, int dstlen);

PVOID WINAPI SHLockSharedEx(HANDLE hData, DWORD dwProcessId, BOOL bWriteAccess);

DWORD WINAPI SHGetValueGoodBootA(HKEY hkey, LPCSTR pSubKey, LPCSTR pValue,
                                 LPDWORD pwType, LPVOID pvData, LPDWORD pbData);
DWORD WINAPI SHGetValueGoodBootW(HKEY hkey, LPCWSTR pSubKey, LPCWSTR pValue,
                                 LPDWORD pwType, LPVOID pvData, LPDWORD pbData);
HRESULT WINAPI SHLoadRegUIStringA(HKEY hkey, LPCSTR value, LPSTR buf, DWORD size);
HRESULT WINAPI SHLoadRegUIStringW(HKEY hkey, LPCWSTR value, LPWSTR buf, DWORD size);
#ifdef UNICODE
#define SHGetValueGoodBoot SHGetValueGoodBootW
#define SHLoadRegUIString  SHLoadRegUIStringW
#else
#define SHGetValueGoodBoot SHGetValueGoodBootA
#define SHLoadRegUIString  SHLoadRegUIStringA
#endif

int
WINAPIV
ShellMessageBoxWrapW(
  _In_opt_ HINSTANCE hAppInst,
  _In_opt_ HWND hWnd,
  _In_ LPCWSTR lpcText,
  _In_opt_ LPCWSTR lpcTitle,
  _In_ UINT fuStyle,
  ...);

/* dwWhich flags for PathFileExistsDefExtW and PathFindOnPathExW */
#define WHICH_PIF       (1 << 0)
#define WHICH_COM       (1 << 1)
#define WHICH_EXE       (1 << 2)
#define WHICH_BAT       (1 << 3)
#define WHICH_LNK       (1 << 4)
#define WHICH_CMD       (1 << 5)
#define WHICH_OPTIONAL  (1 << 6)

#define WHICH_DEFAULT   (WHICH_PIF | WHICH_COM | WHICH_EXE | WHICH_BAT | WHICH_LNK | WHICH_CMD)

BOOL WINAPI PathFileExistsDefExtW(LPWSTR lpszPath, DWORD dwWhich);
BOOL WINAPI PathFindOnPathExW(LPWSTR lpszFile, LPCWSTR *lppszOtherDirs, DWORD dwWhich);
VOID WINAPI FixSlashesAndColonW(LPWSTR);
BOOL WINAPI PathIsValidCharW(WCHAR c, DWORD dwClass);

#ifdef __cplusplus
} /* extern "C" */
#endif /* defined(__cplusplus) */

#endif /* __SHLWAPI_UNDOC_H */

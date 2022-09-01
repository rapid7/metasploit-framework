#pragma once

#include <comdef.h>
#pragma comment(lib, "rpcrt4.lib")

typedef enum UsoAction {
	USO_STARTSCAN,
	USO_STARTDOWNLOAD,
	USO_STARTINSTALL,
	USO_REFRESHSETTINGS,
	USO_STARTINTERACTIVESCAN,
	USO_RESTARTDEVICE,
	USO_SCANINSTALLWAIT,
	USO_RESUMEUPDATE
} UsoAction;

class MiniUsoClient
{
private:
	bool _ready = false;
	void ThrowOnError(HRESULT hResult);

public:
	MiniUsoClient();
	~MiniUsoClient();

public:
	bool Run(UsoAction action);
};

struct Struct_5 {
	int Member0;
	int Member4;
};

struct Struct_23 {
	GUID Member0;
	int Member10;
};

struct Struct_24 {
	int Member0;
	int Member4;
	int Member8;
};

struct Struct_25 {
	int Member0;
	int Member4;
};

struct Struct_26 {
	int Member0;
	int Member4;
	struct Struct_5 Member8;
	struct Struct_25 Member10;
};

struct Struct_33 {
	int Member0;
	int Member4;
};

struct Struct_49 {
	short Member0;
	short Member2;
	short Member4;
	short Member6;
	short Member8;
	short MemberA;
	short MemberC;
	short MemberE;
};

class __declspec(uuid("d960b85b-11b6-4442-a45c-771283ed293a")) IUsoUpdate : public IUnknown {
public:
	virtual HRESULT __stdcall Proc3(struct Struct_26* p0) = 0;
	virtual HRESULT __stdcall Proc4(int* p0) = 0;
	virtual HRESULT __stdcall Proc5(int* p0) = 0;
	virtual HRESULT __stdcall Proc6(BSTR* p0) = 0;
	virtual HRESULT __stdcall Proc7(BSTR* p0) = 0;
	virtual HRESULT __stdcall Proc8(short* p0) = 0;
	virtual HRESULT __stdcall Proc9(struct Struct_23* p0) = 0;
	virtual HRESULT __stdcall Proc10(BSTR* p0, int* p1) = 0; // HRESULT Proc10(/* Stack Offset: 8 */ [Out] /* C:(FC_TOP_LEVEL_CONFORMANCE)(16)(FC_DEREFERENCE)(FC_LONG)(0) */ BSTR[]* p0, /* Stack Offset: 16 */ [Out] int* p1);
	virtual HRESULT __stdcall Proc11(BSTR* p0) = 0;
	virtual HRESULT __stdcall Proc12(double* p0) = 0;
	virtual HRESULT __stdcall Proc13(VARIANT* p0) = 0;
	virtual HRESULT __stdcall Proc14(BSTR* p0) = 0;
	virtual HRESULT __stdcall Proc15(long* p0) = 0;
	virtual HRESULT __stdcall Proc16(long* p0) = 0;
	virtual HRESULT __stdcall Proc17(long* p0) = 0;
	virtual HRESULT __stdcall Proc18() = 0;
	virtual HRESULT __stdcall Proc19(BSTR p0, VARIANT* p1) = 0;
	virtual HRESULT __stdcall Proc20(BSTR p0, VARIANT* p1) = 0;
	virtual HRESULT __stdcall Proc21(int p0, VARIANT* p1) = 0;
	virtual HRESULT __stdcall Proc22() = 0;
};

_COM_SMARTPTR_TYPEDEF(IUsoUpdate, __uuidof(IUsoUpdate));


class __declspec(uuid("a1e78367-46b7-4ac8-affa-d9f55645223b")) IUsoUpdateCollection : public IUnknown {
public:
	virtual HRESULT __stdcall Proc3(int p0, IUsoUpdate** p1) = 0;
	virtual HRESULT __stdcall Proc4(IUnknown** p0) = 0;
	virtual HRESULT __stdcall Proc5(int* p0) = 0;
	virtual HRESULT __stdcall Proc6() = 0;
	virtual HRESULT __stdcall Proc7(int p0) = 0;
};

_COM_SMARTPTR_TYPEDEF(IUsoUpdateCollection, __uuidof(IUsoUpdateCollection));


class __declspec(uuid("580cf13a-20a4-4adc-9322-6dcb8f5c0d0c")) IUsoUpdateHistoryEntry : public IUnknown {
public:
	virtual HRESULT __stdcall Proc3(struct Struct_23* p0) = 0;
	virtual HRESULT __stdcall Proc4(int* p0) = 0;
	virtual HRESULT __stdcall Proc5(int* p0) = 0;
	virtual HRESULT __stdcall Proc6(int* p0) = 0;
	virtual HRESULT __stdcall Proc7(double* p0) = 0;
	virtual HRESULT __stdcall Proc8(BSTR* p0) = 0;
	virtual HRESULT __stdcall Proc9(BSTR* p0) = 0;
	virtual HRESULT __stdcall Proc10(BSTR* p0) = 0;
	virtual HRESULT __stdcall Proc11(int* p0) = 0;
	virtual HRESULT __stdcall Proc12(BSTR* p0, int* p1) = 0; // HRESULT Proc12(/* Stack Offset: 8 */ [Out] /* C:(FC_TOP_LEVEL_CONFORMANCE)(16)(FC_DEREFERENCE)(FC_LONG)(0) */ BSTR[]* p0, /* Stack Offset: 16 */ [Out] int* p1);
	virtual HRESULT __stdcall Proc13(int* p0) = 0;
	virtual HRESULT __stdcall Proc14(BSTR* p0) = 0;
};

_COM_SMARTPTR_TYPEDEF(IUsoUpdateHistoryEntry, __uuidof(IUsoUpdateHistoryEntry));


class __declspec(uuid("7b51947d-62f0-4e71-af2d-c337dff99e57")) IUsoUpdateHistoryEntryCollection : public IUnknown {
public:
	virtual HRESULT __stdcall Proc3(int* p0) = 0;
	virtual HRESULT __stdcall Proc4(int p0, IUsoUpdateHistoryEntry** p1) = 0;
};

_COM_SMARTPTR_TYPEDEF(IUsoUpdateHistoryEntryCollection, __uuidof(IUsoUpdateHistoryEntryCollection));


class __declspec(uuid("b357f841-2130-454e-802c-5c398b549f8e")) IUsoSession : public IUnknown {
public:
	virtual HRESULT __stdcall Proc3(GUID* p0) = 0;
	virtual HRESULT __stdcall Proc4(int* p0) = 0;
	virtual HRESULT __stdcall Proc5(struct Struct_24* p0) = 0;
	virtual HRESULT __stdcall Proc6(struct Struct_25* p0) = 0;
	virtual HRESULT __stdcall Proc7(int p0, IUsoUpdateCollection** p1) = 0;
	virtual HRESULT __stdcall Proc8(int* p0) = 0;
	virtual HRESULT __stdcall Proc9(struct Struct_5* p0) = 0;
	virtual HRESULT __stdcall Proc10(struct Struct_5* p0) = 0;
	virtual HRESULT __stdcall Proc11(struct Struct_5* p0) = 0;
	virtual HRESULT __stdcall Proc12(int* p0) = 0;
	virtual HRESULT __stdcall Proc13(int* p0) = 0;
	virtual HRESULT __stdcall Proc14(short* p0) = 0;
	virtual HRESULT __stdcall Proc15(BSTR* p0) = 0;
	virtual HRESULT __stdcall Proc16(BSTR* p0) = 0;
	virtual HRESULT __stdcall Proc17(int* p0) = 0;
	virtual HRESULT __stdcall Proc18() = 0;
	virtual HRESULT __stdcall Proc19() = 0;
	virtual HRESULT __stdcall Proc20(int p0, int p1, int* p2, short p3, short p4, int p5) = 0;
	virtual HRESULT __stdcall Proc21(short p0, short p1, const wchar_t* p2) = 0; // Proc21(short p0, short p1, wchar_t* p2) = 0;
	virtual HRESULT __stdcall Proc22(short p0) = 0;
	virtual HRESULT __stdcall Proc23(short p0) = 0;
	virtual HRESULT __stdcall Proc24() = 0;
	virtual HRESULT __stdcall Proc25(int p0, int p1, IUsoUpdateHistoryEntryCollection** p2) = 0;
	virtual HRESULT __stdcall Proc26(int* p0) = 0;
	virtual HRESULT __stdcall Proc27(int* p0) = 0;
	virtual HRESULT __stdcall Proc28(wchar_t* p0, int p1, wchar_t* p2) = 0; // HRESULT Proc28(/* Stack Offset: 8 */ [In] /* C:(FC_TOP_LEVEL_CONFORMANCE)(16)(FC_ZERO)(FC_ULONG)(0) */ /* unique */wchar_t*[]* p0, /* Stack Offset: 16 */ [In] int p1, /* Stack Offset: 24 */ [In] wchar_t* p2);
	virtual HRESULT __stdcall Proc29(int p0, wchar_t* p1, int p2) = 0; // HRESULT Proc29(/* Stack Offset: 8 */ [In] int p0, /* Stack Offset: 16 */ [Out] /* (FC_TOP_LEVEL_CONFORMANCE)(24)(FC_ZERO)(FC_ULONG)(0) */wchar_t[1]* p1, /* Stack Offset: 24 */ [In] int p2);
	virtual HRESULT __stdcall Proc30() = 0;
	virtual HRESULT __stdcall Proc31(int p0) = 0;
};

_COM_SMARTPTR_TYPEDEF(IUsoSession, __uuidof(IUsoSession));

class IUsoSettingObject;
class __declspec(uuid("da4baa07-66c8-499a-828d-ba8ff181717c")) IUsoSettingArray : public IUnknown {
public:
	virtual HRESULT __stdcall Proc3(int p0, VARIANT* p1) = 0;
	virtual HRESULT __stdcall Proc4(int* p0) = 0;
	virtual HRESULT __stdcall Proc5(int p0, IUsoSettingObject** p1) = 0;
	virtual HRESULT __stdcall Proc6(int p0, IUsoSettingArray** p1) = 0;
};

_COM_SMARTPTR_TYPEDEF(IUsoSettingArray, __uuidof(IUsoSettingArray));


class __declspec(uuid("edb89974-450a-4370-be41-70132df7119e")) IUsoSettingObject : public IUnknown {
public:
	virtual HRESULT __stdcall Proc3(wchar_t* p0, VARIANT* p1) = 0;
	virtual HRESULT __stdcall Proc4(wchar_t* p0, IUsoSettingObject** p1) = 0;
	virtual HRESULT __stdcall Proc5(wchar_t* p0, IUsoSettingArray** p1) = 0;
};

_COM_SMARTPTR_TYPEDEF(IUsoSettingObject, __uuidof(IUsoSettingObject));


class __declspec(uuid("fccc288d-b47e-41fa-970c-935ec952f4a4")) IUsoSessionCommon : public IUsoSession {
public:
	virtual HRESULT __stdcall Proc32(IUsoUpdateCollection** p0) = 0;
	virtual HRESULT __stdcall Proc33(short* p0) = 0;
	virtual HRESULT __stdcall Proc34(short* p0) = 0;
	virtual HRESULT __stdcall Proc35(short p0) = 0;
	virtual HRESULT __stdcall Proc36(int p0) = 0;
	virtual HRESULT __stdcall Proc37(int* p0) = 0;
	virtual HRESULT __stdcall Proc38(wchar_t* p0, VARIANT* p1) = 0;
	virtual HRESULT __stdcall Proc39(wchar_t* p0, VARIANT* p1) = 0;
	virtual HRESULT __stdcall Proc40(int p0, VARIANT* p1) = 0;
	virtual HRESULT __stdcall Proc41(int p0, VARIANT* p1) = 0;
	virtual HRESULT __stdcall Proc42(wchar_t* p0, wchar_t* p1, wchar_t* p2) = 0;
	virtual HRESULT __stdcall Proc43(wchar_t* p0, wchar_t* p1, wchar_t* p2) = 0;
	virtual HRESULT __stdcall Proc44(int p0, VARIANT* p1, int* p2) = 0;
	virtual HRESULT __stdcall Proc45(int p0, long* p1, long* p2) = 0;
	virtual HRESULT __stdcall Proc46() = 0;
	virtual HRESULT __stdcall Proc47(int p0, short p1, VARIANT* p2) = 0;
	virtual HRESULT __stdcall Proc48(int p0, int p1, int p2, int* p3) = 0;
	virtual HRESULT __stdcall Proc49(int p0, VARIANT* p1, int* p2) = 0;
	virtual HRESULT __stdcall Proc50(int* p0) = 0;
	virtual HRESULT __stdcall Proc51(wchar_t* p0, VARIANT* p1) = 0;
	virtual HRESULT __stdcall Proc52() = 0;
	virtual HRESULT __stdcall Proc53(wchar_t* p0, VARIANT* p1) = 0;
	virtual HRESULT __stdcall Proc54(int* p0) = 0;
	virtual HRESULT __stdcall Proc55() = 0;
	virtual HRESULT __stdcall Proc56(wchar_t* p0, VARIANT* p1) = 0;
	virtual HRESULT __stdcall Proc57(int p0, VARIANT* p1, int* p2, int* p3) = 0;
	virtual HRESULT __stdcall Proc58(int p0, VARIANT* p1, int* p2, int* p3) = 0;
	virtual HRESULT __stdcall Proc59(int p0, IUsoSettingObject** p1) = 0;
	virtual HRESULT __stdcall Proc60(int p0, IUsoSettingArray** p1) = 0;
	virtual HRESULT __stdcall Proc61() = 0;
	virtual HRESULT __stdcall Proc62() = 0;
	virtual HRESULT __stdcall Proc63() = 0;
	virtual HRESULT __stdcall Proc64(int p0, int* p1) = 0;
	virtual HRESULT __stdcall Proc65(int* p0, int* p1, struct Struct_33* p2) = 0;
	virtual HRESULT __stdcall Proc66(IUsoUpdateCollection** p0) = 0;
	virtual HRESULT __stdcall Proc67() = 0;
	virtual HRESULT __stdcall Proc68() = 0;
};

_COM_SMARTPTR_TYPEDEF(IUsoSessionCommon, __uuidof(IUsoSessionCommon));


class __declspec(uuid("a244654f-a777-4739-a8e2-5fd4abbd6799")) IUsoSessionCollection : public IUnknown {
public:
	virtual HRESULT __stdcall Proc3(int* p0) = 0;
	virtual HRESULT __stdcall Proc4(int p0, IUsoSession** p1) = 0;
};

_COM_SMARTPTR_TYPEDEF(IUsoSessionCollection, __uuidof(IUsoSessionCollection));


class __declspec(uuid("833ee9a0-2999-432c-8ef2-87a8ec2d748d")) IUxUpdateManager : public IUnknown {
public:
	virtual HRESULT __stdcall Proc3(int p0, int* p1, int* p2) = 0;
	virtual HRESULT __stdcall Proc4(int p0, int* p1, int* p2) = 0;
	virtual HRESULT __stdcall Proc5(int p0, struct Struct_49* p1, int* p2) = 0;
	virtual HRESULT __stdcall Proc6(int p0, int p1) = 0;
	virtual HRESULT __stdcall Proc7(int p0, int p1) = 0;
	virtual HRESULT __stdcall Proc8(int p0, struct Struct_49* p1) = 0;
	virtual HRESULT __stdcall Proc9(int p0) = 0;
	virtual HRESULT __stdcall Proc10(int* p0, struct Struct_49* p1) = 0;
	virtual HRESULT __stdcall Proc11(wchar_t* p0, struct Struct_49* p1) = 0;
	virtual HRESULT __stdcall Proc12() = 0;
	virtual HRESULT __stdcall Proc13() = 0;
	virtual HRESULT __stdcall Proc14() = 0;
	virtual HRESULT __stdcall Proc15(struct Struct_49* p0) = 0;
	virtual HRESULT __stdcall Proc16() = 0;
	virtual HRESULT __stdcall Proc17(int* p0) = 0;
	virtual HRESULT __stdcall Proc18() = 0;
	virtual HRESULT __stdcall Proc19() = 0;
	virtual HRESULT __stdcall Proc20() = 0;
	virtual HRESULT __stdcall Proc21() = 0;
	virtual HRESULT __stdcall Proc22() = 0;
	virtual HRESULT __stdcall Proc23() = 0;
	virtual HRESULT __stdcall Proc24(int p0, int p1, int* p2, short p3, short p4, int p5) = 0;
	virtual HRESULT __stdcall Proc25(int p0, int p1, int p2, int* p3) = 0;
	virtual HRESULT __stdcall Proc26(int p0, int p1, int* p2) = 0;
	virtual HRESULT __stdcall Proc27(int p0, VARIANT* p1, int* p2, int* p3) = 0;
	virtual HRESULT __stdcall Proc28(int p0, VARIANT* p1, int* p2, int* p3) = 0;
	virtual HRESULT __stdcall Proc29(int p0, short p1, VARIANT* p2) = 0;
	virtual HRESULT __stdcall Proc30(int* p0) = 0;
	virtual HRESULT __stdcall Proc31(int p0) = 0;
	virtual HRESULT __stdcall Proc32(int p0, int* p1) = 0;
	virtual HRESULT __stdcall Proc33(int* p0) = 0;
};

_COM_SMARTPTR_TYPEDEF(IUxUpdateManager, __uuidof(IUxUpdateManager));


class __declspec(uuid("c53f3549-0dbf-429a-8297-c812ba00742d")) IUniversalOrchestrator : public IUnknown {
public:
	virtual HRESULT __stdcall Proc3(wchar_t* p0, int* p1) = 0;
	virtual HRESULT __stdcall Proc4(wchar_t* p0, wchar_t* p1, wchar_t* p2, wchar_t* p3) = 0;
	virtual HRESULT __stdcall Proc5(wchar_t* p0, int p1) = 0;
};

_COM_SMARTPTR_TYPEDEF(IUniversalOrchestrator, __uuidof(IUniversalOrchestrator));


class __declspec(uuid("07f3afac-7c8a-4ce7-a5e0-3d24ee8a77e0")) IUpdateSessionOrchestrator : public IUnknown {
public:
	virtual HRESULT __stdcall CreateUpdateSession(int param_1, GUID* param_2, IUsoSessionCommon** param_3) = 0; 
	virtual HRESULT __stdcall GetCurrentActiveUpdateSessions(IUsoSessionCollection** param_1) = 0; 
	virtual HRESULT __stdcall LogTaskRunning(const wchar_t* param_1) = 0; 
	virtual HRESULT __stdcall CreateUxUpdateManager(IUxUpdateManager** param_1) = 0; 
	virtual HRESULT __stdcall CreateUniversalOrchestrator(IUniversalOrchestrator** param_1) = 0; 
};

_COM_SMARTPTR_TYPEDEF(IUpdateSessionOrchestrator, __uuidof(IUpdateSessionOrchestrator));


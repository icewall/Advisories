Cisco Talos Vulnerability Report
TALOS-CAN-XXX

Ruby DLN module for *nix systems multiple vulnerabilities.

:: Description

Ruby DLN module parsing a.out binary file structures does not make proper values sanitization. These values are later use in calculation of buffer size, as a loop counter...,
but lack of their sanitization opens possibility to Integer overflows vulnerabilities, read/write out of bounds,etc.
 

:: Tested Versions

Ruby 2.3.0 dev

:: Product URLs

https://www.ruby-lang.org


:: Details

====================================================
1. load_lib	:: Out of Bound Read | Access violation
====================================================

------------------------- code -----------------------------
static int
load_lib(const char *lib)
{
	(...)
962    size = read(fd, &ahdr, sizeof(ahdr));
963    if (size == -1) goto syserr;
964    if (size != sizeof(ahdr) || sscanf(ahdr.ar_size, "%d", &size) != 1) {
965    goto badlib;
966    }
967
968    if (strncmp(ahdr.ar_name, "__.SYMDEF", 9) == 0) {
969    /* make hash table from __.SYMDEF */
970
971    lib_tbl = st_init_strtable();
972    data = (int*)xmalloc(size);
973    if (data == NULL) goto syserr;
974    size = read(fd, data, size);             // lack of check how much data have been read
975    nsym = *data / sizeof(struct symdef);   // *data which is int is fully controlled by attacker and has influence on loop counter
976    base = (struct symdef*)(data + 1);
977    name_base = (char*)(base + nsym) + sizeof(int);
978    while (nsym > 0) {
979        char *name = name_base + base->rb_str_index;
980
981        st_insert(lib_tbl, name, base->lib_offset + sizeof(ahdr));
982        nsym--;
983        base++;
984    }
------------------------- code -----------------------------
After reading portion of data with size "size" into variable "data" in Line 974 later we don't see condition checking whether assumed amount of data was really read which can 
cause later out of bound read. In Line 975 we see calculation which result should be number of symdef structures "nsym", but because "*data" integer variable is fully controlled
by attacker "nsym" which is used later in loop as a counter can be set nearly to any value from range <0, (UINT_MAX/ sizeof(symdef))>. Bigger value of "nsym" than reall amount of symdef structures
will lead to out of bound read/access violation (Ruby MRI crash) in while loop.



==============================================================
2. load_text_data :: Integer Overflow | Write Out of Bound
==============================================================

------------------------- code -----------------------------
713 block = load_text_data(fd, &hdr, hdr.a_bss + new_common, disp);
(...)
426	static long
427	load_text_data(int fd, struct exec *hdrp, int bss, long disp)
428	{
429		int size;
430		unsigned char* addr;
431	
432		lseek(fd, disp + N_TXTOFF(*hdrp), 0);
433		size = hdrp->a_text + hdrp->a_data; //integer overflow
434	
435		if (bss == -1) size += hdrp->a_bss;  // \______ integer overflow
436		else if (bss > 1) size += bss;   	 // /
437	
438		addr = (unsigned char*)xmalloc(size);
439		if (addr == NULL) {
440			dln_errno = errno;
441			return 0;
442		}
443	
444		if (read(fd, addr, size) !=  size) {
445			dln_errno = errno;
446			free(addr);
447			return 0;
448		}
449	
450		if (bss == -1) {
451			memset(addr +  hdrp->a_text + hdrp->a_data, 0, hdrp->a_bss);
452		}
453		else if (bss > 0) {
454			memset(addr +  hdrp->a_text + hdrp->a_data, 0, bss);
455		}
456	
457		return (long)addr;
458	}
------------------------- code -----------------------------
In Line 438 variable "size" which is result of addition fields "a_text","a_data","a_bss" is used to allocate memory. Values of all fields are fully controlable 
by attacker and were not sanitized in anyhow before these (and after) calculations. Properlly chosen values of mentioned fields can lead to integer overflow and in result
smaller buffer size allocation than their sum and in consequences write out of bound in line 450 or 454.


:: Credit 

Discovered by Marcin ‘Icewall’ Noga of Sourcefire VRT

:: Timeline

2015-05-05 - Initial Discovery 
2014-XX-XX - Vendor Notification
2014-XX-XX - Patch Released
2014-XX-XX - Public Disclosure
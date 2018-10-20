def uftrace_exit(ctx):
	main_error(ctx)

def main_error(ctx):
	if ctx["name"] == "main" :
		if "retval" in ctx:
			if ctx["retval"] == 0 :
				print("completed successfully.")
			if ctx["retval"] == 1 :
				print("EPERM : Operation not permitted")
			if ctx["retval"] == 2 :
				print("ENOENT : No such file or directory")
			if ctx["retval"] == 3 :
				print("ESRCH : No such process")
				print("No such process ")
			if ctx["retval"] == 4 :
				print("EINTR : interrupted system call")
			if ctx["retval"] == 5 :
				print("EIO : I/O error")
			if ctx["retval"] == 6 :
				print("ENXIO : No such device or address")
			if ctx["retval"] == 7 :
				print("E2BIG : Arg list too long ")
			if ctx["retval"] == 8 :
				print("ENOEXEC : Exec format error")
			if ctx["retval"] == 9 :
				print("EBADF : Bad file descriptor")
			if ctx["retval"] == 10 :
				print("ECHILD : No child processes ")
			if ctx["retval"] == 11 :
				print("EAGAIN : Resource temporarily unavailable")
			if ctx["retval"] == 12 :
				print("ENOMEM : Not enough space")
			if ctx["retval"] == 13 :
				print("EACCES : Permission denied")
			if ctx["retval"] == 14 :
				print("EFAULT : Bad address")
			if ctx["retval"] == 15 :
				print("ENOTBLK : Block device required")
			if ctx["retval"] == 16 :
				print("EBUSY : Resource busy")
			if ctx["retval"] == 17 :
				print("EEXIST : File exists")
			if ctx["retval"] == 18 :
				print("EXDEV : Improper link")
			if ctx["retval"] == 19 :
				print("ENODEV : No such device")
			if ctx["retval"] == 20 :
				print("ENOTDIR : Not a directory")
			if ctx["retval"] == 21 :
				print("EISDIR : Is a directory")
			if ctx["retval"] == 22 :
				print("EINVAL : Invalid argument")
			if ctx["retval"] == 23 :
				print("ENFILE : Too many open files in system")
			if ctx["retval"] == 24 :
				print("EMFILE : Too many open files")				
			if ctx["retval"] == 25 :
				print("ENOTTY : Inappropriate I/O control operation")
			if ctx["retval"] == 26 :
				print("ETXTBSY : Text file busy")
			if ctx["retval"] == 27 :
				print("EFBIG : File too large")
			if ctx["retval"] == 28 :
				print("ENOSPC : No space left on device")
			if ctx["retval"] == 29 :
				print("ESPIPE : Invalid seek")
			if ctx["retval"] == 30 :
				print("EROFS : Read only file system")
			if ctx["retval"] == 31 :
				print("EMLINK : Too many links")
			if ctx["retval"] == 32 :
				print("EPIPE : Broken pipe")
			if ctx["retval"] == 33 :
				print("EDOM : Domain error within math function")
			if ctx["retval"] == 34 :
				print("ERANGE : Result too large")
			if ctx["retval"] == 35 :
				print("ENOMSG : No message of desired type ")

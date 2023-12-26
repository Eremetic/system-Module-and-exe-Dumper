PROJECT FOR REVERSE ENGINEERING

Files Up to date as of - 12/26/2023 @ 5:24pm est

includes kernel module dumper via kernel driver, 
Process Dumper via kernel driver, 
create suspended process,

It has also been a training ground for learning, I've included unhooking all dlls, system token hijack via kernel driver, adding hardware breakpoint to suspended process via thread context.

done via console app just for feel. Though i know winform or wpf would be much more user friendly.


TODO list:

Still Implementing process dumper. been attacking it via physical memory but still have a lot to learn, 
specificlly reading CR3 and walking PML4 to get the proper pages mapped to contiguous memory allocation then dump the process.

still need to finish hardware breakpoint. Not throwing any errors but also not hitting the breakpoint
 
!Fix Leaked Driver Device

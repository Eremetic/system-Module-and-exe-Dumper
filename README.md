project for reverse engineering. 

includes kernel module dumper via kernel driver, 
Process Dumper via kernel driver, 
create suspended process,

It has also been a training ground for learning, I've included unhooking all dlls, system token hijack via kernel driver, adding hardware breakpoint to suspended process via thread context.

done via console app just for feel. Though i know winform or wpf would be much more user friendly.

Still Implementing process dumper. been attacking it via physical memory but still have a lot to learn, 
specificlly reading CR3 and walking PML4 to get the proper pages to map to contiguous memory allocation to dump the process.

PROJECT FOR REVERSE ENGINEERING

Files Up to date as of - 3/24/2023

includes kernel module dumper via kernel driver, 
Process Dumper via kernel driver, 


It has also been a training ground for learning, I've included unhooking all dlls, system token hijack via kernel driver, advanced dump that create process with debug flag effectivly setting a debug breakpoint at entry point.

done via console app just for feel. Though i know winform or wpf would be much more user friendly.

Currently just using a GDRVLoader exploit to load the driver, thank you "Zer0Condition" it has been reliable.

Thank you  Lazaro, C5pider, mrd0x, NULL, and idov31 cant thank them enough for their help learning and working through problems on this project so far.


this project includes functions for using physical memory but it doesnt use it for the dump as you cant lock physical pages of remote process
without attaching to process.

TODO list:

!Fix Leaked Driver Device, so you can unload driver


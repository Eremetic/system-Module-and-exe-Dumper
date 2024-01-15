PROJECT FOR REVERSE ENGINEERING

Files Up to date as of - 1/15/2023 @ 5:36am est

includes kernel module dumper via kernel driver, 
Process Dumper via kernel driver, 


It has also been a training ground for learning, I've included unhooking all dlls, system token hijack via kernel driver, adding hardware breakpoint to suspended process via thread context.

done via console app just for feel. Though i know winform or wpf would be much more user friendly.

 Currently just using a GDRVLoader exploit to load the driver, thank you "Zer0Condition" it has been reliable.

 I cant thank  Lazaro, C5pider, mrd0x, NULL, and idov31 cant thank them enough for their help learning and working through problems on this project so far.

 
TODO list:

almost done  standard dumper

implement adv dump with suspended process and hardware breakpoint via driver

implement gdrv.sys trace cleaning from loading driver

call driver functions at runtime as to stack spoof

!Fix Leaked Driver Device

# 360.cn-Persistance
360.cn has various MTIRE rules to detect various Persistance methods, It even stop any access of Reg Keys/Execution of CMD/PS/Rundll32 possibly via FltRegisterFilter.
It will also disallow you to write any files to startup/sys32.
But for some reason it doesn't flag creation of a scheduled task from COM Objects, bind your UAC Bypass and it will become a weaponized feature for your crypts/applications.
Alternatively you can use TaskScheduler lib in C#, it does the same thing using COM API.


https://github.com/sexyiam/360.cn-Persistance/assets/158042876/b158c3aa-2c8b-4b1b-a20b-b147acf70380


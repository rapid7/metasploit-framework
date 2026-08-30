svn info | grep Revision > revision.txt
7z a '-xr!?svn/' ../DLLHijackAuditKit.zip ./
rm -f revision.txt


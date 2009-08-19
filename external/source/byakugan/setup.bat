# Assumes that Debugging Tools for Windows is installed in C:\windbg

set DBGSDK_INC_PATH=C:\windbg\sdk\inc
set DBGSDK_LIB_PATH=C:\windbg\sdk\lib
set DBGLIB_LIB_PATH=C:\windbg\sdk\lib

REM build byakugan
build -cZMg

REM build injectsu
 cd injectsu\
 build -cZMg
 cd ..

copy /Y i386\byakugan.dll C:\windbg\winext\
copy /Y injectsu\i386\injectsu.dll C:\windbg\

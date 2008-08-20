set DBGSDK_INC_PATH=C:\windbg\sdk\inc
set DBGSDK_LIB_PATH=C:\windbg\sdk\lib
set DBGLIB_LIB_PATH=C:\windbg\sdk\lib

#the following are for jcs 3d stuff#

set SDL_LIB_PATH=C:\Developer\SDL_SDK\lib
set SDL_INC_PATH=C:\Developer\SDL_SDK\include


#build 3dheapfu
cd 3dheapfu\
build -cZMg
cd ..


@echo off

echo Compiling DLLs

for /D %%d in (dll*) do (
  pushd "%%d"
  call build.bat
  popd
)

echo Compiling EXEs

for /D %%e in (exe*) do (
  pushd "%%e"
  call build.bat
  popd
)

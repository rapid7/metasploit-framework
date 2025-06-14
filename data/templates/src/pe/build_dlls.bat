@echo off

for /D %%d in (dll*) do (
  pushd "%%d"
  build.bat
  popd
)
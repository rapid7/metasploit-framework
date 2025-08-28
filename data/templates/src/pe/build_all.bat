@echo off

for /D %%d in (dll*) do (
  pushd "%%d"
  build.bat
  popd
)

for /D %%d in (exe*) do (
  pushd "%%d"
  build.bat
  popd
)


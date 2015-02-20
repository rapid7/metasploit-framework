@echo off
REM Set PATH to location of your WiX binaries
SET PATH=%PATH%;c:\tools\local\wix38-binaries\
@echo on

candle template_windows.wxs
light template_windows.wixobj
copy template_windows.msi ..\..\template_windows.msi
del template_windows.msi
del template_windows.wixobj
del template_windows.wixpdb

candle template_nouac_windows.wxs
light template_nouac_windows.wixobj
copy template_nouac_windows.msi ..\..\template_nouac_windows.msi
del template_nouac_windows.msi
del template_nouac_windows.wixobj
del template_nouac_windows.wixpdb
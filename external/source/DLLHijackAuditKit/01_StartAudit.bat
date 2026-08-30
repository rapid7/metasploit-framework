@set BASE=%~dp0
@cd %BASE%

@echo [*] Starting the audit...
@cscript /nologo audit.js

pause
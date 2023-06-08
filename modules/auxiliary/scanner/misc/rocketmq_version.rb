### This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache RocketMQ Version Scanner',
        'Description' => %q{
          Version scanner for the Apache RocketMQ product.
        },
        'Author' => [
          'h00die',
          'Malayke' # CVE-2023-33246 code
        ],
        'References' => [
          ['URL', 'https://github.com/Malayke/CVE-2023-33246_RocketMQ_RCE_EXPLOIT/blob/main/check.py'],
          ['URL', 'https://github.com/apache/rocketmq']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options([ Opt::RPORT(9876) ])
  end

  def get_version(id)
    # from https://github.com/apache/rocketmq/blob/develop/common/src/4d82b307ef50f5cba5717d0ebafeb3cabf336873/java/org/apache/rocketmq/common/MQVersion.java
    version_list = JSON.parse(File.read(::File.join(Msf::Config.data_directory, 'rocketmq_versions_list.json'), mode: 'rb'))
    version_list.fetch(id, "UNKNOWN_VERSION_ID_#{id})")
  end

  def run_host(_ip)
    # https://github.com/Malayke/CVE-2023-33246_RocketMQ_RCE_EXPLOIT/blob/e27693a854a8e3b2863dc366f36002107e3595de/check.py#L68
    data = '{"code":105,"extFields":{"Signature":"/u5P/wZUbhjanu4LM/UzEdo2u2I=","topic":"TBW102","AccessKey":"rocketmq2"},"flag":0,"language":"JAVA","opaque":1,"serializeTypeCurrentRPC":"JSON","version":401}'
    data_length = "\x00\x00\x00" + [data.length].pack('C')
    header = "\x00\x00\x00" + [data.length + data_length.length].pack('C')

    begin
      connect
      vprint_status('Sending request')
      sock.send(header + data_length + data, 0)
      res = sock.recv(1024)
    rescue Rex::AddressInUse, ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => e
      print_error("Unable to connect: #{e.class} #{e.message}\n#{e.backtrace * "\n"}")
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    ensure
      disconnect
    end

    if res.nil?
      vprint_error('No response received')
      return
    end

    unless res.include?('{')
      vprint_error('Response contains unusable data')
      return
    end

    # remove a response header so we have json-ish data
    res = res[8..]

    # we have 2 json objects appended to eachother, so we now need to split that out and make it usable
    res = res.split('}{')

    jsonable = []
    # patch back in the { and }
    res.each do |r|
      r += '}' unless r.end_with?('}')
      r = '{' + r unless r.start_with?('{')
      jsonable.append(r)
    end

    parsed_data = {}
    # grab some data that we need/want out of the response
    jsonable.each do |j|
      begin
        res = JSON.parse(j)
      rescue JSON::ParserError
        vprint_error("Unable to parse json data: #{j}")
        next
      end
      parsed_data['version'] = get_version(res['version']).gsub('_', '.') if res['version']
      parsed_data['brokerDatas'] = res['brokerDatas'] if res['brokerDatas']
    end

    if parsed_data == {}
      vprint_error('Unable to find version or other data within response.')
      return
    end
    print_good("RocketMQ version #{parsed_data['version']} found with brokers: #{res['brokerDatas']}")
  end
end

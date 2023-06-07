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
    register_options([ Opt::RPORT(9876), ])
  end

  def get_version(id)
    # from https://github.com/apache/rocketmq/blob/develop/common/src/main/java/org/apache/rocketmq/common/MQVersion.java
    version_list = ['V3_0_0_SNAPSHOT', 'V3_0_0_ALPHA1', 'V3_0_0_BETA1', 'V3_0_0_BETA2', 'V3_0_0_BETA3', 'V3_0_0_BETA4', 'V3_0_0_BETA5', 'V3_0_0_BETA6_SNAPSHOT', 'V3_0_0_BETA6', 'V3_0_0_BETA7_SNAPSHOT', 'V3_0_0_BETA7', 'V3_0_0_BETA8_SNAPSHOT', 'V3_0_0_BETA8', 'V3_0_0_BETA9_SNAPSHOT', 'V3_0_0_BETA9', 'V3_0_0_FINAL', 'V3_0_1_SNAPSHOT', 'V3_0_1', 'V3_0_2_SNAPSHOT', 'V3_0_2', 'V3_0_3_SNAPSHOT', 'V3_0_3', 'V3_0_4_SNAPSHOT', 'V3_0_4', 'V3_0_5_SNAPSHOT', 'V3_0_5', 'V3_0_6_SNAPSHOT', 'V3_0_6', 'V3_0_7_SNAPSHOT', 'V3_0_7', 'V3_0_8_SNAPSHOT', 'V3_0_8', 'V3_0_9_SNAPSHOT', 'V3_0_9', 'V3_0_10_SNAPSHOT', 'V3_0_10', 'V3_0_11_SNAPSHOT', 'V3_0_11', 'V3_0_12_SNAPSHOT', 'V3_0_12', 'V3_0_13_SNAPSHOT', 'V3_0_13', 'V3_0_14_SNAPSHOT', 'V3_0_14', 'V3_0_15_SNAPSHOT', 'V3_0_15', 'V3_1_0_SNAPSHOT', 'V3_1_0', 'V3_1_1_SNAPSHOT', 'V3_1_1', 'V3_1_2_SNAPSHOT', 'V3_1_2', 'V3_1_3_SNAPSHOT', 'V3_1_3', 'V3_1_4_SNAPSHOT', 'V3_1_4', 'V3_1_5_SNAPSHOT', 'V3_1_5', 'V3_1_6_SNAPSHOT', 'V3_1_6', 'V3_1_7_SNAPSHOT', 'V3_1_7', 'V3_1_8_SNAPSHOT', 'V3_1_8', 'V3_1_9_SNAPSHOT', 'V3_1_9', 'V3_2_0_SNAPSHOT', 'V3_2_0', 'V3_2_1_SNAPSHOT', 'V3_2_1', 'V3_2_2_SNAPSHOT', 'V3_2_2', 'V3_2_3_SNAPSHOT', 'V3_2_3', 'V3_2_4_SNAPSHOT', 'V3_2_4', 'V3_2_5_SNAPSHOT', 'V3_2_5', 'V3_2_6_SNAPSHOT', 'V3_2_6', 'V3_2_7_SNAPSHOT', 'V3_2_7', 'V3_2_8_SNAPSHOT', 'V3_2_8', 'V3_2_9_SNAPSHOT', 'V3_2_9', 'V3_3_1_SNAPSHOT', 'V3_3_1', 'V3_3_2_SNAPSHOT', 'V3_3_2', 'V3_3_3_SNAPSHOT', 'V3_3_3', 'V3_3_4_SNAPSHOT', 'V3_3_4', 'V3_3_5_SNAPSHOT', 'V3_3_5', 'V3_3_6_SNAPSHOT', 'V3_3_6', 'V3_3_7_SNAPSHOT', 'V3_3_7', 'V3_3_8_SNAPSHOT', 'V3_3_8', 'V3_3_9_SNAPSHOT', 'V3_3_9', 'V3_4_1_SNAPSHOT', 'V3_4_1', 'V3_4_2_SNAPSHOT', 'V3_4_2', 'V3_4_3_SNAPSHOT', 'V3_4_3', 'V3_4_4_SNAPSHOT', 'V3_4_4', 'V3_4_5_SNAPSHOT', 'V3_4_5', 'V3_4_6_SNAPSHOT', 'V3_4_6', 'V3_4_7_SNAPSHOT', 'V3_4_7', 'V3_4_8_SNAPSHOT', 'V3_4_8', 'V3_4_9_SNAPSHOT', 'V3_4_9', 'V3_5_1_SNAPSHOT', 'V3_5_1', 'V3_5_2_SNAPSHOT', 'V3_5_2', 'V3_5_3_SNAPSHOT', 'V3_5_3', 'V3_5_4_SNAPSHOT', 'V3_5_4', 'V3_5_5_SNAPSHOT', 'V3_5_5', 'V3_5_6_SNAPSHOT', 'V3_5_6', 'V3_5_7_SNAPSHOT', 'V3_5_7', 'V3_5_8_SNAPSHOT', 'V3_5_8', 'V3_5_9_SNAPSHOT', 'V3_5_9', 'V3_6_1_SNAPSHOT', 'V3_6_1', 'V3_6_2_SNAPSHOT', 'V3_6_2', 'V3_6_3_SNAPSHOT', 'V3_6_3', 'V3_6_4_SNAPSHOT', 'V3_6_4', 'V3_6_5_SNAPSHOT', 'V3_6_5', 'V3_6_6_SNAPSHOT', 'V3_6_6', 'V3_6_7_SNAPSHOT', 'V3_6_7', 'V3_6_8_SNAPSHOT', 'V3_6_8', 'V3_6_9_SNAPSHOT', 'V3_6_9', 'V3_7_1_SNAPSHOT', 'V3_7_1', 'V3_7_2_SNAPSHOT', 'V3_7_2', 'V3_7_3_SNAPSHOT', 'V3_7_3', 'V3_7_4_SNAPSHOT', 'V3_7_4', 'V3_7_5_SNAPSHOT', 'V3_7_5', 'V3_7_6_SNAPSHOT', 'V3_7_6', 'V3_7_7_SNAPSHOT', 'V3_7_7', 'V3_7_8_SNAPSHOT', 'V3_7_8', 'V3_7_9_SNAPSHOT', 'V3_7_9', 'V3_8_1_SNAPSHOT', 'V3_8_1', 'V3_8_2_SNAPSHOT', 'V3_8_2', 'V3_8_3_SNAPSHOT', 'V3_8_3', 'V3_8_4_SNAPSHOT', 'V3_8_4', 'V3_8_5_SNAPSHOT', 'V3_8_5', 'V3_8_6_SNAPSHOT', 'V3_8_6', 'V3_8_7_SNAPSHOT', 'V3_8_7', 'V3_8_8_SNAPSHOT', 'V3_8_8', 'V3_8_9_SNAPSHOT', 'V3_8_9', 'V3_9_1_SNAPSHOT', 'V3_9_1', 'V3_9_2_SNAPSHOT', 'V3_9_2', 'V3_9_3_SNAPSHOT', 'V3_9_3', 'V3_9_4_SNAPSHOT', 'V3_9_4', 'V3_9_5_SNAPSHOT', 'V3_9_5', 'V3_9_6_SNAPSHOT', 'V3_9_6', 'V3_9_7_SNAPSHOT', 'V3_9_7', 'V3_9_8_SNAPSHOT', 'V3_9_8', 'V3_9_9_SNAPSHOT', 'V3_9_9', 'V4_0_0_SNAPSHOT', 'V4_0_0', 'V4_0_1_SNAPSHOT', 'V4_0_1', 'V4_0_2_SNAPSHOT', 'V4_0_2', 'V4_0_3_SNAPSHOT', 'V4_0_3', 'V4_0_4_SNAPSHOT', 'V4_0_4', 'V4_0_5_SNAPSHOT', 'V4_0_5', 'V4_0_6_SNAPSHOT', 'V4_0_6', 'V4_0_7_SNAPSHOT', 'V4_0_7', 'V4_0_8_SNAPSHOT', 'V4_0_8', 'V4_0_9_SNAPSHOT', 'V4_0_9', 'V4_1_0_SNAPSHOT', 'V4_1_0', 'V4_1_1_SNAPSHOT', 'V4_1_1', 'V4_1_2_SNAPSHOT', 'V4_1_2', 'V4_1_3_SNAPSHOT', 'V4_1_3', 'V4_1_4_SNAPSHOT', 'V4_1_4', 'V4_1_5_SNAPSHOT', 'V4_1_5', 'V4_1_6_SNAPSHOT', 'V4_1_6', 'V4_1_7_SNAPSHOT', 'V4_1_7', 'V4_1_8_SNAPSHOT', 'V4_1_8', 'V4_1_9_SNAPSHOT', 'V4_1_9', 'V4_2_0_SNAPSHOT', 'V4_2_0', 'V4_2_1_SNAPSHOT', 'V4_2_1', 'V4_2_2_SNAPSHOT', 'V4_2_2', 'V4_2_3_SNAPSHOT', 'V4_2_3', 'V4_2_4_SNAPSHOT', 'V4_2_4', 'V4_2_5_SNAPSHOT', 'V4_2_5', 'V4_2_6_SNAPSHOT', 'V4_2_6', 'V4_2_7_SNAPSHOT', 'V4_2_7', 'V4_2_8_SNAPSHOT', 'V4_2_8', 'V4_2_9_SNAPSHOT', 'V4_2_9', 'V4_3_0_SNAPSHOT', 'V4_3_0', 'V4_3_1_SNAPSHOT', 'V4_3_1', 'V4_3_2_SNAPSHOT', 'V4_3_2', 'V4_3_3_SNAPSHOT', 'V4_3_3', 'V4_3_4_SNAPSHOT', 'V4_3_4', 'V4_3_5_SNAPSHOT', 'V4_3_5', 'V4_3_6_SNAPSHOT', 'V4_3_6', 'V4_3_7_SNAPSHOT', 'V4_3_7', 'V4_3_8_SNAPSHOT', 'V4_3_8', 'V4_3_9_SNAPSHOT', 'V4_3_9', 'V4_4_0_SNAPSHOT', 'V4_4_0', 'V4_4_1_SNAPSHOT', 'V4_4_1', 'V4_4_2_SNAPSHOT', 'V4_4_2', 'V4_4_3_SNAPSHOT', 'V4_4_3', 'V4_4_4_SNAPSHOT', 'V4_4_4', 'V4_4_5_SNAPSHOT', 'V4_4_5', 'V4_4_6_SNAPSHOT', 'V4_4_6', 'V4_4_7_SNAPSHOT', 'V4_4_7', 'V4_4_8_SNAPSHOT', 'V4_4_8', 'V4_4_9_SNAPSHOT', 'V4_4_9', 'V4_5_0_SNAPSHOT', 'V4_5_0', 'V4_5_1_SNAPSHOT', 'V4_5_1', 'V4_5_2_SNAPSHOT', 'V4_5_2', 'V4_5_3_SNAPSHOT', 'V4_5_3', 'V4_5_4_SNAPSHOT', 'V4_5_4', 'V4_5_5_SNAPSHOT', 'V4_5_5', 'V4_5_6_SNAPSHOT', 'V4_5_6', 'V4_5_7_SNAPSHOT', 'V4_5_7', 'V4_5_8_SNAPSHOT', 'V4_5_8', 'V4_5_9_SNAPSHOT', 'V4_5_9', 'V4_6_0_SNAPSHOT', 'V4_6_0', 'V4_6_1_SNAPSHOT', 'V4_6_1', 'V4_6_2_SNAPSHOT', 'V4_6_2', 'V4_6_3_SNAPSHOT', 'V4_6_3', 'V4_6_4_SNAPSHOT', 'V4_6_4', 'V4_6_5_SNAPSHOT', 'V4_6_5', 'V4_6_6_SNAPSHOT', 'V4_6_6', 'V4_6_7_SNAPSHOT', 'V4_6_7', 'V4_6_8_SNAPSHOT', 'V4_6_8', 'V4_6_9_SNAPSHOT', 'V4_6_9', 'V4_7_0_SNAPSHOT', 'V4_7_0', 'V4_7_1_SNAPSHOT', 'V4_7_1', 'V4_7_2_SNAPSHOT', 'V4_7_2', 'V4_7_3_SNAPSHOT', 'V4_7_3', 'V4_7_4_SNAPSHOT', 'V4_7_4', 'V4_7_5_SNAPSHOT', 'V4_7_5', 'V4_7_6_SNAPSHOT', 'V4_7_6', 'V4_7_7_SNAPSHOT', 'V4_7_7', 'V4_7_8_SNAPSHOT', 'V4_7_8', 'V4_7_9_SNAPSHOT', 'V4_7_9', 'V4_8_0_SNAPSHOT', 'V4_8_0', 'V4_8_1_SNAPSHOT', 'V4_8_1', 'V4_8_2_SNAPSHOT', 'V4_8_2', 'V4_8_3_SNAPSHOT', 'V4_8_3', 'V4_8_4_SNAPSHOT', 'V4_8_4', 'V4_8_5_SNAPSHOT', 'V4_8_5', 'V4_8_6_SNAPSHOT', 'V4_8_6', 'V4_8_7_SNAPSHOT', 'V4_8_7', 'V4_8_8_SNAPSHOT', 'V4_8_8', 'V4_8_9_SNAPSHOT', 'V4_8_9', 'V4_9_0_SNAPSHOT', 'V4_9_0', 'V4_9_1_SNAPSHOT', 'V4_9_1', 'V4_9_2_SNAPSHOT', 'V4_9_2', 'V4_9_3_SNAPSHOT', 'V4_9_3', 'V4_9_4_SNAPSHOT', 'V4_9_4', 'V4_9_5_SNAPSHOT', 'V4_9_5', 'V4_9_6_SNAPSHOT', 'V4_9_6', 'V4_9_7_SNAPSHOT', 'V4_9_7', 'V4_9_8_SNAPSHOT', 'V4_9_8', 'V4_9_9_SNAPSHOT', 'V4_9_9', 'V5_0_0_SNAPSHOT', 'V5_0_0', 'V5_0_1_SNAPSHOT', 'V5_0_1', 'V5_0_2_SNAPSHOT', 'V5_0_2', 'V5_0_3_SNAPSHOT', 'V5_0_3', 'V5_0_4_SNAPSHOT', 'V5_0_4', 'V5_0_5_SNAPSHOT', 'V5_0_5', 'V5_0_6_SNAPSHOT', 'V5_0_6', 'V5_0_7_SNAPSHOT', 'V5_0_7', 'V5_0_8_SNAPSHOT', 'V5_0_8', 'V5_0_9_SNAPSHOT', 'V5_0_9', 'V5_1_0_SNAPSHOT', 'V5_1_0', 'V5_1_1_SNAPSHOT', 'V5_1_1', 'V5_1_2_SNAPSHOT', 'V5_1_2', 'V5_1_3_SNAPSHOT', 'V5_1_3', 'V5_1_4_SNAPSHOT', 'V5_1_4', 'V5_1_5_SNAPSHOT', 'V5_1_5', 'V5_1_6_SNAPSHOT', 'V5_1_6', 'V5_1_7_SNAPSHOT', 'V5_1_7', 'V5_1_8_SNAPSHOT', 'V5_1_8', 'V5_1_9_SNAPSHOT', 'V5_1_9', 'V5_2_0_SNAPSHOT', 'V5_2_0', 'V5_2_1_SNAPSHOT', 'V5_2_1', 'V5_2_2_SNAPSHOT', 'V5_2_2', 'V5_2_3_SNAPSHOT', 'V5_2_3', 'V5_2_4_SNAPSHOT', 'V5_2_4', 'V5_2_5_SNAPSHOT', 'V5_2_5', 'V5_2_6_SNAPSHOT', 'V5_2_6', 'V5_2_7_SNAPSHOT', 'V5_2_7', 'V5_2_8_SNAPSHOT', 'V5_2_8', 'V5_2_9_SNAPSHOT', 'V5_2_9', 'V5_3_0_SNAPSHOT', 'V5_3_0', 'V5_3_1_SNAPSHOT', 'V5_3_1', 'V5_3_2_SNAPSHOT', 'V5_3_2', 'V5_3_3_SNAPSHOT', 'V5_3_3', 'V5_3_4_SNAPSHOT', 'V5_3_4', 'V5_3_5_SNAPSHOT', 'V5_3_5', 'V5_3_6_SNAPSHOT', 'V5_3_6', 'V5_3_7_SNAPSHOT', 'V5_3_7', 'V5_3_8_SNAPSHOT', 'V5_3_8', 'V5_3_9_SNAPSHOT', 'V5_3_9', 'V5_4_0_SNAPSHOT', 'V5_4_0', 'V5_4_1_SNAPSHOT', 'V5_4_1', 'V5_4_2_SNAPSHOT', 'V5_4_2', 'V5_4_3_SNAPSHOT', 'V5_4_3', 'V5_4_4_SNAPSHOT', 'V5_4_4', 'V5_4_5_SNAPSHOT', 'V5_4_5', 'V5_4_6_SNAPSHOT', 'V5_4_6', 'V5_4_7_SNAPSHOT', 'V5_4_7', 'V5_4_8_SNAPSHOT', 'V5_4_8', 'V5_4_9_SNAPSHOT', 'V5_4_9', 'V5_5_0_SNAPSHOT', 'V5_5_0', 'V5_5_1_SNAPSHOT', 'V5_5_1', 'V5_5_2_SNAPSHOT', 'V5_5_2', 'V5_5_3_SNAPSHOT', 'V5_5_3', 'V5_5_4_SNAPSHOT', 'V5_5_4', 'V5_5_5_SNAPSHOT', 'V5_5_5', 'V5_5_6_SNAPSHOT', 'V5_5_6', 'V5_5_7_SNAPSHOT', 'V5_5_7', 'V5_5_8_SNAPSHOT', 'V5_5_8', 'V5_5_9_SNAPSHOT', 'V5_5_9', 'V5_6_0_SNAPSHOT', 'V5_6_0', 'V5_6_1_SNAPSHOT', 'V5_6_1', 'V5_6_2_SNAPSHOT', 'V5_6_2', 'V5_6_3_SNAPSHOT', 'V5_6_3', 'V5_6_4_SNAPSHOT', 'V5_6_4', 'V5_6_5_SNAPSHOT', 'V5_6_5', 'V5_6_6_SNAPSHOT', 'V5_6_6', 'V5_6_7_SNAPSHOT', 'V5_6_7', 'V5_6_8_SNAPSHOT', 'V5_6_8', 'V5_6_9_SNAPSHOT', 'V5_6_9', 'V5_7_0_SNAPSHOT', 'V5_7_0', 'V5_7_1_SNAPSHOT', 'V5_7_1', 'V5_7_2_SNAPSHOT', 'V5_7_2', 'V5_7_3_SNAPSHOT', 'V5_7_3', 'V5_7_4_SNAPSHOT', 'V5_7_4', 'V5_7_5_SNAPSHOT', 'V5_7_5', 'V5_7_6_SNAPSHOT', 'V5_7_6', 'V5_7_7_SNAPSHOT', 'V5_7_7', 'V5_7_8_SNAPSHOT', 'V5_7_8', 'V5_7_9_SNAPSHOT', 'V5_7_9', 'V5_8_0_SNAPSHOT', 'V5_8_0', 'V5_8_1_SNAPSHOT', 'V5_8_1', 'V5_8_2_SNAPSHOT', 'V5_8_2', 'V5_8_3_SNAPSHOT', 'V5_8_3', 'V5_8_4_SNAPSHOT', 'V5_8_4', 'V5_8_5_SNAPSHOT', 'V5_8_5', 'V5_8_6_SNAPSHOT', 'V5_8_6', 'V5_8_7_SNAPSHOT', 'V5_8_7', 'V5_8_8_SNAPSHOT', 'V5_8_8', 'V5_8_9_SNAPSHOT', 'V5_8_9', 'V5_9_0_SNAPSHOT', 'V5_9_0', 'V5_9_1_SNAPSHOT', 'V5_9_1', 'V5_9_2_SNAPSHOT', 'V5_9_2', 'V5_9_3_SNAPSHOT', 'V5_9_3', 'V5_9_4_SNAPSHOT', 'V5_9_4', 'V5_9_5_SNAPSHOT', 'V5_9_5', 'V5_9_6_SNAPSHOT', 'V5_9_6', 'V5_9_7_SNAPSHOT', 'V5_9_7', 'V5_9_8_SNAPSHOT', 'V5_9_8', 'V5_9_9_SNAPSHOT', 'V5_9_9', 'HIGHER_VERSION']
    version_list[id]
  end

  def run_host(_ip)
    # https://github.com/Malayke/CVE-2023-33246_RocketMQ_RCE_EXPLOIT/blob/main/check.py#L68
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

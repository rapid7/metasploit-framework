### This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Rocketmq

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
  end

  def run_host(_ip)
    res = send_version_request

    if res.nil?
      print_error('Invalid or no response received')
      return
    end

    parsed_data = parse_rocketmq_data(res)
    # grab some data that we need/want out of the response
    output = "RocketMQ version #{parsed_data['version']}"
    output += " found with brokers: #{parsed_data['brokerDatas']}" if parsed_data['brokerDatas']
    print_good(output)
  end
end

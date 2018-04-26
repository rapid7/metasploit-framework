##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::BrowserExploitServer

  def initialize(info={})
    super(update_info(info,
      'Name'           => "HTTP Client Information Gather",
      'Description'    => %q{
        This module gathers information about a browser that exploits might be interested in, such
        as OS name, browser version, plugins, etc. By default, the module will return a fake 404,
        but you can customize this output by changing the Custom404 datastore option, and
        redirect to an external web page.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'sinn3r' ],
      'DisclosureDate' => "Mar 22 2016",
      'Actions'     =>
        [
          [
            'WebServer', {
              'Description' => 'A web that collects information about the browser.'
          }]
        ],
      'PassiveActions' => [ 'WebServer' ],
      'DefaultAction'  => 'WebServer'
    ))
  end

  def is_key_wanted?(key)
    ![:module, :created_at, :tried, :vuln_test, :address].include?(key)
  end

  def is_value_wanted?(value)
    !(value.nil? || value =~ /^undefined|false/ || !value)
  end

  def ignore_items!(target_info)
    target_info.delete_if do |key, value|
      !is_key_wanted?(key) || !is_value_wanted?(value)
    end
  end

  def report_host_info(target_info)
    opts = { host: target_info[:address] }
    opts.merge!(target_info)
    report_host(opts)
  end

  def translate_script_meaning(value)
    case value
    when 'script'
      'Browser allows JavaScript'
    when 'headers'
      'Browser does not allow JavaScript'
    end
  end

  def print_target_info(cli, target_info)
    print_good("#{cli.peerhost} - We have found the following interesting information:")
    report_host_info(target_info)
    ignore_items!(target_info)
    target_info.each_pair do |key, value|
      if key == :source
        value = translate_script_meaning(value)
      end
      print_status("#{cli.peerhost} - #{key} = #{value}")
    end
  end

  def on_request_exploit(cli, req, target_info)
    print_target_info(cli, target_info)
    send_response(cli, '')
  end

  def run
    exploit
  end
end

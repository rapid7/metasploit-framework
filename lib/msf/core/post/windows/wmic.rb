# -*- coding: binary -*-

module Msf
class Post
module Windows

module WMIC

  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::ExtAPI

  def initialize(info = {})
    super(
      update_info(
        info,
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              extapi_clipboard_get_data
              extapi_clipboard_set_data
              stdapi_railgun_api
              stdapi_sys_process_execute
            ]
          }
        }
      )
    )

    register_options([
                         OptString.new('SMBUser', [ false, 'The username to authenticate as' ], fallbacks: ['USERNAME']),
                         OptString.new('SMBPass', [ false, 'The password for the specified username' ], fallbacks: ['PASSWORD']),
                         OptString.new('SMBDomain',  [ false, 'The Windows domain to use for authentication' ], fallbacks: ['DOMAIN']),
                         OptAddress.new("RHOST", [ true, "Target address range", "localhost" ]),
                         OptInt.new("TIMEOUT", [ true, "Timeout for WMI command in seconds", 10 ])
                     ], self.class)
  end

  def wmic_query(query, server=datastore['RHOST'])
    result_text = ""

    if datastore['SMBUser']
      if server.downcase == "localhost" || server.downcase.starts_with?('127.')
        raise RuntimeError, "WMIC: User credentials cannot be used for local connections"
      end
    end

    if session.commands.include?(Rex::Post::Meterpreter::Extensions::Extapi::COMMAND_ID_EXTAPI_CLIPBOARD_SET_DATA) && !is_system?
      session.extapi.clipboard.set_text("")
      wcmd = "wmic #{wmic_user_pass_string}/output:CLIPBOARD /INTERACTIVE:off /node:#{server} #{query}"
    else
      tmp = get_env('TEMP')
      out_file = "#{tmp}\\#{Rex::Text.rand_text_alpha(8)}"
      wcmd = "cmd.exe /c %SYSTEMROOT%\\system32\\wbem\\wmic.exe #{wmic_user_pass_string}/output:#{out_file} /INTERACTIVE:off /node:#{server} #{query}"
    end

    vprint_status("[#{server}] #{wcmd}")

    # We dont use cmd_exec as WMIC cannot be Channelized
    ps = session.sys.process.execute(wcmd, nil, {'Hidden' => true, 'Channelized' => false})
    session.railgun.kernel32.WaitForSingleObject(ps.handle, (datastore['TIMEOUT'] * 1000))
    ps.close

    if session.commands.include?(Rex::Post::Meterpreter::Extensions::Extapi::COMMAND_ID_EXTAPI_CLIPBOARD_GET_DATA) && !is_system?
      result = session.extapi.clipboard.get_data.first
      if result && result[1] && result[1].has_key?('Text')
        result_text = result[1]['Text']
      else
        result_text = ""
      end
    else
      result_text = Rex::Text.to_ascii(read_file(out_file))[1..-1]
      file_rm(out_file)
    end

    return result_text
  end

  def wmic_command(cmd, server=datastore['RHOST'])
    result_text = wmic_query("process call create \"#{cmd.gsub('"','\\"')}\"", server)

    parsed_result = nil
    unless result_text.blank?
      vprint_status("[#{server}] WMIC Command Result:")
      vprint_line(result_text)
      parsed_result = parse_wmic_result(result_text)
    end

    if parsed_result == nil
      vprint_error("[#{server}] WMIC Command Error")
    end

    return parsed_result
  end

  def parse_wmic_result(result_text)
    if result_text.blank?
      return nil
    else
      pid = nil
      return_value = nil

      if result_text =~ /ProcessId = (\d+);/
        pid = $1.to_i
      end

      if result_text =~ /ReturnValue = (\d+);/
        return_value = $1.to_i
      end

      return {:return => return_value, :pid => pid, :text =>result_text}
    end
  end

  def wmic_user_pass_string(domain=datastore['SMBDomain'], user=datastore['SMBUser'], pass=datastore['SMBPass'])
    userpass = ""

    unless user.nil?
      if domain.nil?
        userpass = "/user:\"#{user}\" /password:\"#{pass}\" "
      else
        userpass = "/user:\"#{domain}\\#{user}\" /password:\"#{pass}\" "
      end
    end

    return userpass
  end

end # WMIC
end # Windows
end # Post
end # Msf

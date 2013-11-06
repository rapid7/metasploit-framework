##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  PRIVATE_KEY = <<-EOF.gsub(/^ {4}/, '')
    -----BEGIN RSA PRIVATE KEY-----
    MIICXQIBAAKBgQC1q1kR6chWLfwspD84Asyy6EFV6SYRGy/gILsYGtn9kCQi2RFo
    bNxS5CvphbGWn9D9n5gJpTVWLWb3LwJxGuBKSRj2wrHLlejzw6kSmF+3xFCuMfxV
    FSj8TM8JqlOqM1c6lvH2MSXnN7pJBVcekNKbBUEfptakPSejStljbXecSwIDAQAB
    AoGAah4/FzGiboTKCyGeNA+eltsIXzCjpdZlrtwvrbLxpyXtldWKT59XS6ww4mXQ
    CJYuNBhnbSrt7vrybG0vVfZHEOCvK+5YKBOtvRgrWDgs1Bkc5hsdI5gLx3jE7g6M
    PuUvD7ueF4OzYeYRrOLWr957jl32n+hD/k65bKWAUp3aTDECQQDqnEPZWlmoH7Jp
    6woRnEp+1cullHv8DviM5Huh+JeBotSa03p4unhKlRYSqnHdeHU2343n1VUDzvnV
    LQWi5G+FAkEAxjt0S67lyuuVD842uZRHt2WSQvwt23aKzQ+EJwV0IXYzfefeLzEm
    dDdvc1AJ31gweAQK89/5/1EEF40K7BJdjwJBAJDFdtTT/QlS7eyQPjlZwVp9IVp+
    wvdqYZPHlkb/uLYlPZ6Aq01+e6ZCU0mXZgYtQ99lmhKaQQjFmsMiMh0va2UCQA2T
    NLuaFpJ235ZdgNHknaSpiAKeUmWdEJRKY7poXTONbKlKn6SLsR50TWWQLZzl5SvS
    2w0oYW5ile0m84CHIXECQQCrABn0HY4Ll9/4FX+OCWamqwENltU1GcGIogeyFymK
    ZVX8QdAVoUiZoUaVku946j63WNSkI1sU/UWhL6XDt4gx
    -----END RSA PRIVATE KEY-----
  EOF


  def initialize
    super(
      'Name'        => 'Supermicro Onboard IPMI Static SSL Certificate Scanner',
      'Description' => %q{
        This module checks for a static SSL certificate shipped with Supermicro Onboard IPMI
        controllers. An attacker with access to the publicly-available firmware can perform 
        man-in-the-middle attacks and offline decryption of communication to the controller.
        This module has been on a Supermicro Onboard IPMI (X9SCL/X9SCM) with firmware
        version SMT_X9_214.
      },
      'Author'       =>
        [
          'hdm', # Discovery and analysis
          'juan' # Metasploit module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE', '2013-3619' ],
          [ 'URL', 'https://community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities']
        ],
      'DisclosureDate' => 'Nov 06 2013'
    )

    register_options(
      [
        Opt::RPORT(443),
      ], self.class)
  end

  # Fingerprint a single host
  def run_host(ip)
    connect(true, {"SSL" => true}) #Force SSL
    cert  = OpenSSL::X509::Certificate.new(sock.peer_cert)
    disconnect

    unless cert
      vprint_error("#{ip}:#{rport} - No certificate found")
      return
    end

    pkey = OpenSSL::PKey::RSA.new(PRIVATE_KEY)
    result = cert.verify(pkey)

    if result
      print_good("#{ip}:#{rport} - Vulnerable to CVE-2013-3619 (Static SSL Certificate)")
      # Report with the the SSL Private Key hash for the host
      digest = OpenSSL::Digest::SHA1.new(pkey.public_key.to_der).to_s.scan(/../).join(":")
      report_note(
        :host  => ip,
        :proto => 'tcp',
        :port  => rport,
        :type  => 'supermicro.ipmi.ssl.certificate.pkey_hash',
        :data  => digest
      )

      report_vuln({
        :host  => rhost,
        :port  => rport,
        :proto => 'tcp',
        :name  => "Supermicro Onboard IPMI Static SSL Certificate",
        :refs  => self.references
      })
    end
  end

end

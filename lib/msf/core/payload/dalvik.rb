# -*- coding: binary -*-
require 'msf/core'

module Msf::Payload::Dalvik

  #
  # Fix the dex header checksum and signature
  # http://source.android.com/tech/dalvik/dex-format.html
  #
  def fix_dex_header(dexfile)
    dexfile = dexfile.unpack('a8LH40a*')
    dexfile[2] = Digest::SHA1.hexdigest(dexfile[3])
    dexfile[1] = Zlib.adler32(dexfile[2..-1].pack('H40a*'))
    dexfile.pack('a8LH40a*')
  end

  #
  # We could compile the .class files with dx here
  #
  def generate_stage
  end

  #
  # Used by stagers to construct the payload jar file as a String
  #
  def generate
    generate_jar.pack
  end

  def java_string(str)
    [str.length].pack("N") + str
  end

  def string_sub(data, placeholder="", input="")
    data.gsub!(placeholder, input + ' ' * (placeholder.length - input.length))
  end

  def generate_cert
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
    cert.not_after = cert.not_before + 3600*24*365*20 # 20 years
    return cert, key
  end
end


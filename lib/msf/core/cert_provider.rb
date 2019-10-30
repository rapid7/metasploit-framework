require 'rex/socket/ssl'
require 'faker'

module Msf
module Ssl
  module CertProvider

    def self.rand_vars(opts = {})
      opts ||= {}
      opts[:cc] ||= 'US'
      opts[:st] ||= Faker::Address.state_abbr
      opts[:loc] ||= Faker::Address.city
      opts[:org] ||= Faker::Company.name
      opts[:ou] ||= Faker::Hacker.send(%w{noun verb adjective}.sample.to_sym).gsub(/\W+/,'.')
      opts[:cn] ||= opts[:org].downcase.gsub(/and/,'').gsub(/\W+/,'.') + '.' +  Faker::Internet.domain_suffix
      opts[:email] ||= "#{opts[:ou]}@#{opts[:cn]}"
      opts
    end

    def self.ssl_generate_subject(opts = {})
      opts = self.rand_vars(opts)
      subject = ""
      subject << "/C=#{opts[:cc]}" if opts[:cc]
      subject << "/ST=#{opts[:st]}" if opts[:st]
      subject << "/O=#{opts[:org]}" if opts[:org]
      subject << "/OU=#{opts[:ou]}" if opts[:ou]
      subject << "/CN=#{opts[:cn]}" if opts[:cn]
      subject << "/emailAddress=#{opts[:email]}" if opts[:email]
      subject
    end

    # Not used, for API compatibility
    def self.ssl_generate_issuer(
      cc: 'US',
      org: Faker::Company.name,
      cn: Faker::Internet.domain_name
    )
      "#{cc}/O=#{org}/CN=#{cn}"
    end

    #
    # Generate a realistic-looking but obstensibly fake SSL
    # certificate. Use Faker gem to mimic other self-signed
    # certificates on the web to reduce the chance of sig
    # identification by NIDS and the like.
    #
    # @return [String, String, Array]
    def self.ssl_generate_certificate(cert_vars: {}, ksize: 2048, **opts)
      yr      = 24*3600*365
      vf      = opts[:not_before] || Time.at(Time.now.to_i - rand(yr * 3) - yr)
      vt      = opts[:not_after]  || Time.at(vf.to_i + (rand(9)+1) * yr)
      cvars   = self.rand_vars(cert_vars)
      subject = opts[:subject]    || ssl_generate_subject(cvars)
      ctype   = opts[:cert_type]  || opts[:ca_cert].nil? ? :ca : :server
      key     = opts[:key] || OpenSSL::PKey::RSA.new(ksize){ }
      cert    = OpenSSL::X509::Certificate.new

      cert.version    = opts[:version] || 2
      cert.serial     = opts[:serial]  || (rand(0xFFFFFFFF) << 32) + rand(0xFFFFFFFF)
      cert.subject    = OpenSSL::X509::Name.parse(subject)
      cert.issuer     = opts[:ca_cert] || cert.subject
      cert.not_before = vf
      cert.not_after  = vt
      cert.public_key = key.public_key

      bconst, kuse, ekuse = case ctype
      when :ca
        ['CA:TRUE', 'cRLSign,keyCertSign']
      when :server
        ['CA:FALSE', 'digitalSignature,keyEncipherment', 'serverAuth']
      when :client
        ['CA:FALSE', 'nonRepudiation,digitalSignature,keyEncipherment', 'clientAuth,emailProtection']
      when :ocsp
        ['CA:FALSE', 'nonRepudiation,digitalSignature', 'serverAuth,OCSPSigning']
      when :tsca
        ['CA:TRUE,pathlen:0', 'cRLSign,keyCertSign']
      end

      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = cert
      ef.issuer_certificate = cert
      cert.extensions = [
        ef.create_extension("basicConstraints", bconst, true),
        ef.create_extension("subjectKeyIdentifier", "hash")
      ]
      if kuse and !kuse.empty?
        cert.extensions << ef.create_extension("keyUsage", kuse)
      end

      if ekuse and !ekuse.empty?
        cert.extensions << ef.create_extension("extendedKeyUsage", ekuse)
      end

      cert.sign(key, OpenSSL::Digest::SHA256.new)

      [key, cert, nil]
    end
  end
end
end

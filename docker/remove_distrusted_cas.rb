#!/usr/bin/env ruby
# frozen_string_literal: true

# Removes certificates for distrusted certificate authorities from the PEM CA
# bundles passed as arguments. Used when building the Docker image so that these
# roots are not shipped. Bundles are rewritten in place.
#
# Covers the eMudhra intermediate CA compromise (private keys of 8 intermediates
# leaked; each cross-signed under an eMudhra root and under Comodo/Sectigo's
# "AAA Certificate Services" root). Trust bundles only ship roots, so the
# compromised intermediates themselves never appear here; instead this distrusts
# the roots the advisory lists as the signing paths for those intermediates.
# See https://emudhra.we-have-a-problem.com/ (roots.json) and
# https://support.apple.com/en-us/149555
#
# Usage: remove_distrusted_cas.rb BUNDLE [BUNDLE ...]

require 'openssl'
require 'set'

# SHA-256 fingerprints (DER, uppercase hex) of distrusted roots, matched exactly
# rather than by name to avoid over-matching unrelated certificates from the
# same issuer. Sourced from https://emudhra.we-have-a-problem.com/roots.json
DISTRUSTED_FINGERPRINTS = Set[
  '7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D', # emSign Root TLS CA - G3
  'F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5', # emSign Root CS CA - G3
  '86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B', # emSign ECC Root CA - G3
  'D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4', # AAA Certificate Services (Comodo/Sectigo cross-sign)
].freeze

PEM_CERTIFICATE = /-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----\n?/m.freeze

ARGV.each do |path|
  removed = 0
  kept = 0
  bundle = File.read(path).gsub(PEM_CERTIFICATE) do |pem|
    cert = OpenSSL::X509::Certificate.new(pem)
    fingerprint = OpenSSL::Digest::SHA256.hexdigest(cert.to_der).upcase
    if DISTRUSTED_FINGERPRINTS.include?(fingerprint)
      removed += 1
      ''
    else
      kept += 1
      pem
    end
  end

  File.write(path, bundle)
  puts "#{path}: kept=#{kept} removed=#{removed}"
end

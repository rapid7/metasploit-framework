module Msf
  module Trace
    class CertificateTrace

      SEPARATOR = '[CertTrace] ' + ('-' * 45)

      def self.print_metadata(cert, mod)
        return unless cert

        mod.print_line(SEPARATOR)

        subject = cert.subject.to_s rescue 'unknown'
        issuer  = cert.issuer.to_s rescue 'unknown'

        mod.print_line(" Subject : #{subject}")
        mod.print_line(" Issuer  : #{issuer}")
      end

      def self.print_full(cert, mod)
        print_metadata(cert, mod)

        not_before = cert.not_before rescue nil
        not_after  = cert.not_after rescue nil

        mod.print_line(" Valid From : #{not_before}") if not_before
        mod.print_line(" Valid To   : #{not_after}") if not_after
      end

    end
  end
end

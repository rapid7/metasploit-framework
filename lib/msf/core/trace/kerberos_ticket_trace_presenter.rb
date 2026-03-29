# -*- coding: binary -*-

module Msf
  module Trace
    # Presenter for Kerberos TGT responses.
    #
    # Follows the same responsibility split as
    # Rex::Proto::Kerberos::CredentialCache::Krb5CCachePresenter:
    # this class constructs formatted strings only. The caller (module instance)
    # is responsible for invoking its own print methods so output is correctly
    # associated with the running module.
    #
    # Usage:
    #   presenter = Msf::Trace::KerberosTicketTracePresenter.new(response)
    #   mod.print_line(presenter.to_s_metadata)
    #   mod.print_line(presenter.to_s_full)
    class KerberosTicketTracePresenter

      SEPARATOR = '[KerberosTrace] ' + ('-' * 41)

      # @param response [Msf::Exploit::Remote::Kerberos::Model::TgtResponse]
      def initialize(response)
        @response = response
        @as_rep   = response&.as_rep
        @dec      = response&.decrypted_part
      end

      # Returns a formatted metadata string: realm, principal, enc type.
      # Safe to call when as_rep or any nested field is nil.
      #
      # @return [String, nil]
      def to_s_metadata
        return nil unless @as_rep

        realm  = @as_rep.crealm
        cname  = @as_rep.cname&.name_string&.join('/') || 'unknown'
        etype  = @as_rep.enc_part&.etype || 'unknown'

        [
          SEPARATOR,
          "  Principal : #{realm} / #{cname}",
          "  Enc Type  : #{etype}"
        ].join("\n")
      end

      # Returns a formatted full string including all available fields.
      #
      # Session keys and cipher text are printed in plain text — Metasploit does
      # not censor key material, and these fields are frequently needed for
      # debugging and development work.
      #
      # Falls back gracefully when decrypted_part is nil (e.g. AS-REP roasting).
      #
      # @return [String, nil]
      def to_s_full
        base = to_s_metadata
        return nil unless base

        lines = [base]

        if @dec
          lines << "  Start        : #{@dec.starttime}"
          lines << "  End          : #{@dec.endtime}"

          flags = if @dec.flags.respond_to?(:join)
                    @dec.flags.join(', ')
                  else
                    @dec.flags.to_s
                  end
          lines << "  Flags        : #{flags}"

          # Session key — printed in plain text per Metasploit convention.
          lines << "  Session Key  : #{@dec.key}" if @dec.respond_to?(:key) && @dec.key
        end

        # Cipher text — nil-safe guard on enc_part before checking cipher.
        if @as_rep.enc_part&.respond_to?(:cipher) && @as_rep.enc_part.cipher
          lines << "  Cipher Text  : #{@as_rep.enc_part.cipher}"
        end

        lines.join("\n")
      end

      # Returns a censored full string: timing and flags only, key material omitted.
      #
      # This mode exists as a convenience for operators who want structured ticket
      # output without sensitive fields. The primary 'full' mode always includes
      # session keys and cipher text. This mode is not the default.
      #
      # @return [String, nil]
      def to_s_full_censored
        base = to_s_metadata
        return nil unless base
        return base unless @dec

        flags = if @dec.flags.respond_to?(:join)
                  @dec.flags.join(', ')
                else
                  @dec.flags.to_s
                end

        [
          base,
          "  Start        : #{@dec.starttime}",
          "  End          : #{@dec.endtime}",
          "  Flags        : #{flags}"
        ].join("\n")
      end
    end
  end
end
# -*- coding: binary -*-

module Msf
  module Trace
    class KerberosTicketTrace

      SEPARATOR = '[KerberosTrace] ' + ('-' * 41)

      def self.print_metadata(response, mod)
        return unless response&.as_rep

        as_rep = response.as_rep

        realm = as_rep.crealm
        cname = as_rep.cname&.name_string&.join('/')
        etype = as_rep.enc_part&.etype || 'unknown'

        mod.print_line(SEPARATOR)
        mod.print_line(" Principal : #{realm} / #{cname}")
        mod.print_line(" Enc Type : #{etype}")
      end

      def self.print_full(response, mod)
        print_metadata(response, mod)

        dec = response.decrypted_part
        return unless dec

        mod.print_line(" Start : #{dec.starttime}")
        mod.print_line(" End : #{dec.endtime}")

        flags = if dec.flags.respond_to?(:join)
                  dec.flags.join(', ')
                else
                  dec.flags.to_s
                end

        mod.print_line(" Flags : #{flags}")
      end

    end
  end
end
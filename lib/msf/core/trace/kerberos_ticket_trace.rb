module Msf
module Trace

class KerberosTicketTrace

  def self.print(response, framework_module, level: :metadata)

    return unless response

    as_rep = response.as_rep

    framework_module.print_status("[KerberosTrace] ------------------")

    if as_rep
      framework_module.print_status("Msg Type : #{as_rep.msg_type}") if as_rep.respond_to?(:msg_type)
      framework_module.print_status("Enc Type : #{as_rep.enc_part.etype}") if as_rep.respond_to?(:enc_part)
    end

    if level == :full && response.decrypted_part
      dec = response.decrypted_part

      framework_module.print_status("Client   : #{dec.cname}") if dec.respond_to?(:cname)
      framework_module.print_status("Realm    : #{dec.crealm}") if dec.respond_to?(:crealm)
      framework_module.print_status("Start    : #{dec.starttime}") if dec.respond_to?(:starttime)
      framework_module.print_status("End      : #{dec.endtime}") if dec.respond_to?(:endtime)
    end

  end

end

end
end

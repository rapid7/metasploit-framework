# -*- coding: binary -*-


###
#
# A specialization of the {Exploit exploit module class} that is geared
# toward exploits that are performed locally.  Locally, in this case,
# is defined as an exploit that is realized by means other than
# network communication.
#
###
class Msf::Exploit::Local < Msf::Exploit
  include Msf::PostMixin

  #
  # Returns the fact that this exploit is a local exploit.
  #
  def exploit_type
    Msf::Exploit::Type::Local
  end

  def run_simple(opts = {}, &block)
    Msf::Simple::Exploit.exploit_simple(self, opts, &block)
  end
end

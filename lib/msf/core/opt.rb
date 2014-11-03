# -*- coding: binary -*-

module Msf

###
#
# The core supported option types are:
#
# OptString  - Multi-byte character string
# OptRaw     - Multi-byte raw string
# OptBool    - Boolean true or false indication
# OptPort    - TCP/UDP service port
# OptAddress - IP address or hostname
# OptPath    - Path name on disk or an Object ID
# OptInt     - An integer value
# OptEnum    - Select from a set of valid values
# OptAddressRange - A subnet or range of addresses
# OptSession - A session identifier
# OptRegexp  - Valid Ruby regular expression
#
###

#
# Builtin framework options with shortcut methods
#
module Opt

@@builtin_opts =
  {
    'RHOST' => [ Msf::OptAddress, 'nil',   true,  '"The target address"' ],
    'RPORT' => [ Msf::OptPort,    'nil',   true,  '"The target port"' ],
    'LHOST' => [ Msf::OptAddress, 'nil',   true,  '"The listen address"' ],
    'LPORT' => [ Msf::OptPort,    'nil',   true,  '"The listen port"' ],
    'CPORT' => [ Msf::OptPort,    'nil',   false, '"The local client port"' ],
    'CHOST' => [ Msf::OptAddress, 'nil',   false, '"The local client address"' ],
    'Proxies' => [ Msf::OptString, 'nil',  'false', '"A proxy chain of format type:host:port[,type:host:port][...]"']
  }

#
# Build the builtin_xyz methods on the fly using the type information for each
# of the builtin framework options, such as RHOST.
#
class <<self
  @@builtin_opts.each_pair { |opt, info|
    eval(
      "
      def builtin_#{opt.downcase}(default = #{info[1]}, required = #{info[2]}, desc = #{info[3]})
        #{info[0]}.new('#{opt}', [ required, desc, default ])
      end

      alias #{opt} builtin_#{opt.downcase}
      ")
  }
end

#
# Define the constant versions of the options which are merely redirections to
# the class methods.
#
@@builtin_opts.each_pair { |opt, info|
  eval("#{opt} = Msf::Opt::builtin_#{opt.downcase}")
}

end

end

##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Multi Manage Post Module Macro Execution',
        'Description'   => %q{
            This module will execute a list of modules given in a macro file in the format
            of <module> <opt=val,opt=val> against the select session checking for compatibility
            of the module against the sessions and validation of the options provided.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ '<carlos_perez[at]darkoperator.com>'],
        'Platform'      => [ 'win', 'unix', 'osx', 'linux', 'solaris' ],
        'SessionTypes'  => [ 'meterpreter','shell' ]
      ))
    register_options(
      [

        OptString.new('MACRO', [true, 'File with Post Modules and Options to run in the session', nil])

      ], self.class)
  end

  # Run Method for when run command is issued
  def run
    # syinfo is only on meterpreter sessions
    print_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?
    macro = datastore['MACRO']
    entries = []
    if not ::File.exists?(macro)
      print_error "Resource File does not exists!"
      return
    else
      ::File.open(datastore['MACRO'], "rb").each_line do |line|
        # Empty line
        next if line.strip.length < 1
        # Comment
        next if line[0,1] == "#"
        entries << line.chomp
      end
    end

    if entries
      entries.each do |l|
        values = l.split(" ")
        post_mod = values[0]
        if values.length == 2
          mod_opts = values[1].split(",")
        end
        print_line("Loading #{post_mod}")
        # Make sure we can handle post module names with or without post in the start
        if post_mod =~ /^post\//
          post_mod.gsub!(/^post\//,"")
        end
        m = framework.post.create(post_mod)

        # Check if a post module was actually initiated
        if m.nil?
          print_error("Post module #{post_mod} could not be initialized!")
          next
        end
        # Set the current session
        s = datastore['SESSION']

        if m.session_compatible?(s.to_i)
          print_line("Running Against #{s}")
          m.datastore['SESSION'] = s
          if mod_opts
            mod_opts.each do |o|
              opt_pair = o.split("=",2)
              print_line("\tSetting Option #{opt_pair[0]} to #{opt_pair[1]}")
              m.datastore[opt_pair[0]] = opt_pair[1]
            end
          end
          m.options.validate(m.datastore)
          m.run_simple(
            'LocalInput'    => self.user_input,
            'LocalOutput'    => self.user_output
          )
        else
          print_error("Session #{s} is not compatible with #{post_mod}")
        end

      end
      else
        print_error("Resource file was empty!")
      end
  end
end

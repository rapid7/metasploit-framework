##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/common'

class Metasploit3 < Msf::Post

  include Msf::Post::Common

  def initialize(info={})
    super( update_info( info,
      'Name'          => "OS X Text to Speech Utility",
      'Description'   => %q{
        This module will speak whatever is in the 'TEXT' option on the victim machine.
      },
      'References'    =>
        [
          ['URL', 'http://www.gabrielserafini.com/blog/2008/08/19/mac-os-x-voices-for-using-with-the-say-command/']
        ],
      'License'       => MSF_LICENSE,
      'Author'        => [ 'sinn3r'],
      'Platform'      => [ 'osx' ],
      'SessionTypes'  => [ "shell" ]
    ))

  register_options(
    [
      OptString.new('TEXT',  [true, 'The text to say', "meta-sploit\!"]),
      OptString.new('VOICE', [true, 'The voice to use', 'alex'])
    ], self.class)
  end


  def exec(cmd)
    tries = 0
    begin
      out = cmd_exec(cmd).chomp
    rescue ::Timeout::Error => e
      tries += 1
      if tries < 3
        vprint_error("#{@peer} - #{e.message} - retrying...")
        retry
      end
    rescue EOFError => e
      tries += 1
      if tries < 3
        vprint_error("#{@peer} - #{e.message} - retrying...")
        retry
      end
    end
  end


  def run
    txt = datastore['TEXT']
    voice = datastore['VOICE']

    # Say the text
    out = cmd_exec("say -v \"#{voice}\" \"#{txt}\"")
    if out =~ /command not found/
      print_error("The remote machine does not have the \'say\' command")
    elsif not out.empty?
      print_status(out)
    end
  end

end
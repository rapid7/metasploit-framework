# -*- coding: binary -*-
require 'pp'
require 'rex'
require 'msf/ui/web/driver'

module Msf
module RPC
class RPC_Console < RPC_Base

  def initialize(*args)
    super
    @console_driver = Msf::Ui::Web::Driver.new(:framework => framework)
  end

  def rpc_create(opts={})
    cid = @console_driver.create_console(opts)
    {
      'id'     => cid,
      'prompt' => @console_driver.consoles[cid].prompt || '',
      'busy'   => @console_driver.consoles[cid].busy   || false
    }
  end

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

  def rpc_destroy(cid)
    cid = cid.to_s
    return { 'result' => 'failure' } if not @console_driver.consoles[cid]
    res = @console_driver.destroy_console(cid)
    { 'result' => res ? 'success' : 'failure' }
  end

  def rpc_read(cid)
    cid = cid.to_s
    return { 'result' => 'failure' } if not @console_driver.consoles[cid]
    {
      "data"   => @console_driver.read_console(cid)    || '',
      "prompt" => @console_driver.consoles[cid].prompt || '',
      "busy"   => @console_driver.consoles[cid].busy   || false
    }
  end

  def rpc_write(cid, data)
    cid = cid.to_s
    return { 'result' => 'failure' } if not @console_driver.consoles[cid]
    { "wrote" => @console_driver.write_console(cid, data || '') }
  end

  def rpc_tabs(cid, line)
    cid = cid.to_s
    return { 'result' => 'failure' } if not @console_driver.consoles[cid]
    { "tabs" => @console_driver.consoles[cid].tab_complete(line) }
  end

  def rpc_session_kill(cid)
    cid = cid.to_s
    return { 'result' => 'failure' } if not @console_driver.consoles[cid]
    @console_driver.consoles[cid].session_kill
    { 'result' => 'success' }
  end

  def rpc_session_detach(cid)
    cid = cid.to_s
    return { 'result' => 'failure' } if not @console_driver.consoles[cid]
    @console_driver.consoles[cid].session_detach
    { 'result' => 'success' }
  end


end
end
end


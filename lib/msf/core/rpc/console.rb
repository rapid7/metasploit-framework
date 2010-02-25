require 'pp'
require 'rex'
require 'msf/ui/web/driver'

module Msf
module RPC
class Console < Base

	def initialize(framework,tokens,users)
		super(framework, tokens, users)
		@console_driver = Msf::Ui::Web::Driver.new(:framework => framework)
	end

	def create(token)
		authenticate(token)
		cid = @console_driver.create_console
		{
			'id'     => cid,
			'prompt' => @console_driver.consoles[cid].prompt || '',
			'busy'   => @console_driver.consoles[cid].busy   || false
		}
	end

	def list(token)
		authenticate(token)
		ret = []
		@console_driver.consoles.each_key do |k|
			ret << {
				'id'     => k,
				'prompt' => @console_driver.consoles[k].prompt || '',
				'busy'   => @console_driver.consoles[k].busy   || false
			}
		end
		{'consoles' => ret}
	end

	def destroy(token, cid)
		authenticate(token)
		return { 'result' => 'failure' } if not @console_driver.consoles[cid]
		res = @console_driver.destroy_console(cid)
		{ 'result' => res ? 'success' : 'failure' }
	end

	def read(token, cid)
		authenticate(token)
		return { 'result' => 'failure' } if not @console_driver.consoles[cid]
		{
			"data"   => @console_driver.read_console(cid)    || '',
			"prompt" => @console_driver.consoles[cid].prompt || '',
			"busy"   => @console_driver.consoles[cid].busy   || false
		 }
	end

	def write(token, cid, data)
		authenticate(token)
		return { 'result' => 'failure' } if not @console_driver.consoles[cid]
		{ "wrote" => @console_driver.write_console(cid, data) || '' }
	end

	def tabs(token, cid, line)
		authenticate(token)
		return { 'result' => 'failure' } if not @console_driver.consoles[cid]
		{ "tabs" => @console_driver.consoles[cid].tab_complete(line) }
	end

	def session_kill(token, cid)
		authenticate(token)
		return { 'result' => 'failure' } if not @console_driver.consoles[cid]
		@console_driver.consoles[cid].session_kill
		{ 'result' => 'success' }
	end

	def session_detach(token, cid)
		authenticate(token)
		return { 'result' => 'failure' } if not @console_driver.consoles[cid]
		@console_driver.consoles[cid].session_detach
		{ 'result' => 'success' }
	end


end
end
end


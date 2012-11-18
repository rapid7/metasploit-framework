# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_wldap32

	def self.create_dll(dll_path = 'wldap32')
		dll = DLL.new(dll_path, ApiConstants.manager)

		dll.add_function( 'ldap_sslinitW', 'PDWORD',[
				['PCHAR', 'HostName', 'in'],
				['DWORD', 'PortNumber', 'in'],
				['DWORD', 'secure', 'in']
		])
				
		dll.add_function( 'ldap_simple_bind_sW', 'DWORD',[
				['DWORD', 'ld', 'in'],
				['PCHAR', 'dn', 'in'],
				['PCHAR', 'passwd', 'in']
		])

		return dll
	end

end

end; end; end; end; end; end; end



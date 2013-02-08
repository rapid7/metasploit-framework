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

		dll.add_function('ldap_sslinitA', 'DWORD',[
				['PCHAR', 'HostName', 'in'],
				['DWORD', 'PortNumber', 'in'],
				['DWORD', 'secure', 'in']
		])

		dll.add_function('ldap_bind_sA', 'DWORD',[
				['DWORD', 'ld', 'in'],
				['PCHAR', 'dn', 'in'],
				['PCHAR', 'cred', 'in'],
				['DWORD', 'method', 'in']
		])

		dll.add_function('ldap_search_sA', 'DWORD',[
				['DWORD', 'ld', 'in'],
				['PCHAR', 'base', 'in'],
				['DWORD', 'scope', 'in'],
				['PCHAR', 'filter', 'in'],
				['PCHAR', 'attrs[]', 'in'],
				['DWORD', 'attrsonly', 'in'],
				['PDWORD', 'res', 'out']
		])

		dll.add_function('ldap_count_entries', 'DWORD',[
				['DWORD', 'ld', 'in'],
				['DWORD', 'res', 'in']
		])
				dll.add_function('ldap_first_entry', 'DWORD',[
				['DWORD', 'ld', 'in'],
				['DWORD', 'res', 'in']
		])

		dll.add_function('ldap_next_entry', 'DWORD',[
				['DWORD', 'ld', 'in'],
				['DWORD', 'entry', 'in']
		])

		dll.add_function('ldap_first_attributeA', 'DWORD',[
				['DWORD', 'ld', 'in'],
				['DWORD', 'entry', 'in'],
				['DWORD', 'ptr', 'in']
		])

		dll.add_function('ldap_next_attributeA', 'DWORD',[
				['DWORD', 'ld', 'in'],
				['DWORD', 'entry', 'in'],
				['DWORD', 'ptr', 'inout']
		])

		dll.add_function('ldap_count_values', 'DWORD',[
				['DWORD', 'vals', 'in'],
		])

		dll.add_function('ldap_get_values', 'DWORD',[
				['DWORD', 'ld', 'in'],
				['DWORD', 'entry', 'in'],
				['PCHAR', 'attr', 'in']
		])

		dll.add_function('ldap_value_free', 'DWORD',[
				['DWORD', 'vals', 'in'],
		])

		dll.add_function('ldap_memfree', 'VOID',[
				['DWORD', 'block', 'in'],
		])

		dll.add_function('ber_free', 'VOID',[
				['DWORD', 'pBerElement', 'in'],
				['DWORD', 'fbuf', 'in'],
		])

		dll.add_function('LdapGetLastError', 'DWORD',[])

		dll.add_function('ldap_err2string', 'DWORD',[
				['DWORD', 'err', 'in']
		])

		dll.add_function('ldap_msgfree', 'DWORD', [
			['DWORD', 'res', 'in']
		])

		dll.add_function('ldap_unbind', 'DWORD', [
			['DWORD', 'ld', 'in']
		])
		return dll
	end

end

end; end; end; end; end; end; end



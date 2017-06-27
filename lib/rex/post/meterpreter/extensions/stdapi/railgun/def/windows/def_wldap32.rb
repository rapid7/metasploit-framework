# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_windows_wldap32

  def self.create_library(constant_manager, library_path = 'wldap32')
    dll = Library.new(library_path, constant_manager)

    dll.add_function('ldap_sslinitA', 'DWORD',[
        ['PCHAR', 'HostName', 'in'],
        ['DWORD', 'PortNumber', 'in'],
        ['DWORD', 'secure', 'in']
    ], 'ldap_sslinitA', "cdecl")

    dll.add_function('ldap_bind_sA', 'DWORD',[
        ['DWORD', 'ld', 'in'],
        ['PCHAR', 'dn', 'in'],
        ['PCHAR', 'cred', 'in'],
        ['DWORD', 'method', 'in']
    ], 'ldap_bind_sA', "cdecl")

    dll.add_function('ldap_search_sA', 'DWORD',[
        ['DWORD', 'ld', 'in'],
        ['PCHAR', 'base', 'in'],
        ['DWORD', 'scope', 'in'],
        ['PCHAR', 'filter', 'in'],
        ['PCHAR', 'attrs[]', 'in'],
        ['DWORD', 'attrsonly', 'in'],
        ['PDWORD', 'res', 'out']
    ], 'ldap_search_sA', "cdecl")

    dll.add_function('ldap_set_option', 'DWORD',[
        ['DWORD', 'ld', 'in'],
        ['DWORD', 'option', 'in'],
        ['PDWORD', 'invalue', 'in']
    ], 'ldap_set_option', "cdecl")

    dll.add_function('ldap_search_ext_sA', 'DWORD',[
        ['DWORD', 'ld', 'in'],
        ['PCHAR', 'base', 'in'],
        ['DWORD', 'scope', 'in'],
        ['PCHAR', 'filter', 'in'],
        ['PCHAR', 'attrs[]', 'in'],
        ['DWORD', 'attrsonly', 'in'],
        ['DWORD', 'pServerControls', 'in'],
        ['DWORD', 'pClientControls', 'in'],
        ['DWORD', 'pTimeout', 'in'],
        ['DWORD', 'SizeLimit', 'in'],
        ['PDWORD', 'res', 'out']
    ], 'ldap_search_ext_sA', "cdecl")

    dll.add_function('ldap_count_entries', 'DWORD',[
        ['DWORD', 'ld', 'in'],
        ['DWORD', 'res', 'in']
    ], "ldap_count_entries", "cdecl")

    dll.add_function('ldap_first_entry', 'DWORD',[
        ['DWORD', 'ld', 'in'],
        ['DWORD', 'res', 'in']
    ], 'ldap_first_entry', "cdecl")

    dll.add_function('ldap_next_entry', 'DWORD',[
        ['DWORD', 'ld', 'in'],
        ['DWORD', 'entry', 'in']
    ], 'ldap_next_entry', "cdecl")

    dll.add_function('ldap_first_attributeA', 'DWORD',[
        ['DWORD', 'ld', 'in'],
        ['DWORD', 'entry', 'in'],
        ['DWORD', 'ptr', 'in']
    ], 'ldap_first_attributeA', "cdecl")

    dll.add_function('ldap_next_attributeA', 'DWORD',[
        ['DWORD', 'ld', 'in'],
        ['DWORD', 'entry', 'in'],
        ['DWORD', 'ptr', 'inout']
    ], 'ldap_next_attributeA', "cdecl")

    dll.add_function('ldap_count_values', 'DWORD',[
        ['DWORD', 'vals', 'in'],
    ], 'ldap_count_values', "cdecl")

    dll.add_function('ldap_get_values', 'DWORD',[
        ['DWORD', 'ld', 'in'],
        ['DWORD', 'entry', 'in'],
        ['PCHAR', 'attr', 'in']
    ], 'ldap_get_values', "cdecl")

    dll.add_function('ldap_value_free', 'DWORD',[
        ['DWORD', 'vals', 'in'],
    ], 'ldap_value_free', "cdecl")

    dll.add_function('ldap_memfree', 'VOID',[
        ['DWORD', 'block', 'in'],
    ], 'ldap_memfree', "cdecl")

    dll.add_function('ber_free', 'VOID',[
        ['DWORD', 'pBerElement', 'in'],
        ['DWORD', 'fbuf', 'in'],
    ], 'ber_free', "cdecl")

    dll.add_function('LdapGetLastError', 'DWORD',[], 'LdapGetLastError', "cdecl")

    dll.add_function('ldap_err2string', 'DWORD',[
        ['DWORD', 'err', 'in']
    ], 'ldap_err2string', "cdecl")

    dll.add_function('ldap_msgfree', 'DWORD', [
      ['DWORD', 'res', 'in']
    ], 'ldap_msgfree', "cdecl")

    dll.add_function('ldap_unbind', 'DWORD', [
      ['DWORD', 'ld', 'in']
    ], 'ldap_unbind', "cdecl")
    return dll
  end

end

end; end; end; end; end; end; end



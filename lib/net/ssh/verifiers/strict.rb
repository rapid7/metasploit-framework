require 'net/ssh/errors'
require 'net/ssh/known_hosts'

module Net; module SSH; module Verifiers

  # Does a strict host verification, looking the server up in the known
  # host files to see if a key has already been seen for this server. If this
  # server does not appear in any host file, this will silently add the
  # server. If the server does appear at least once, but the key given does
  # not match any known for the server, an exception will be raised (HostKeyMismatch).
  # Otherwise, this returns true.
  class Strict
    def verify(arguments)
      options = arguments[:session].options
      host = options[:host_key_alias] || arguments[:session].host_as_string
      matches = Net::SSH::KnownHosts.search_for(host, arguments[:session].options)

      # we've never seen this host before, so just automatically add the key.
      # not the most secure option (since the first hit might be the one that
      # is hacked), but since almost nobody actually compares the key
      # fingerprint, this is a reasonable compromise between usability and
      # security.
      if matches.empty?
        ip = arguments[:session].peer[:ip]
        Net::SSH::KnownHosts.add(host, arguments[:key], arguments[:session].options)
        return true
      end

      # If we found any matches, check to see that the key type and
      # blob also match.
      found = matches.any? do |key|
        key.ssh_type == arguments[:key].ssh_type &&
        key.to_blob  == arguments[:key].to_blob
      end

      # If a match was found, return true. Otherwise, raise an exception
      # indicating that the key was not recognized.
      found || process_cache_miss(host, arguments)
    end

    private

      def process_cache_miss(host, args)
        exception = HostKeyMismatch.new("fingerprint #{args[:fingerprint]} does not match for #{host.inspect}")
        exception.data = args
        exception.callback = Proc.new do
          Net::SSH::KnownHosts.add(host, args[:key], args[:session].options)
        end
        raise exception
      end
  end

end; end; end
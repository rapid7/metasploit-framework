unless ENV.respond_to? :to_h
  class << ENV
    alias_method :to_h, :to_hash
  end
end

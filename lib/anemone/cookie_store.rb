require 'delegate'
require 'webrick/cookie'

class WEBrick::Cookie
  def expired?
    !!expires && expires < Time.now
  end
end

module Anemone
  class CookieStore < DelegateClass(Hash)

    def initialize(cookies = nil)
      @cookies = {}
      cookies.each { |name, value| @cookies[name] = WEBrick::Cookie.new(name, value) } if cookies
      super(@cookies)
    end

    def merge!(set_cookie_str)
      begin
        cookie_hash = WEBrick::Cookie.parse_set_cookies(set_cookie_str).inject({}) do |hash, cookie|
          hash[cookie.name] = cookie if !!cookie
          hash
        end
        @cookies.merge! cookie_hash
      rescue
      end
    end

    def to_s
      @cookies.values.reject { |cookie| cookie.expired? }.map { |cookie| "#{cookie.name}=#{cookie.value}" }.join(';')
    end

  end
end

#--
# Copyright (c) 2005-2010 Philip Ross
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#++

module TZInfo
  # Thrown by Country#get if the code given is not valid.
  class InvalidCountryCode < StandardError
  end
  
  # An ISO 3166 country. Can be used to get a list of Timezones for a country.
  # For example:
  #
  #  us = Country.get('US')
  #  us.zone_identifiers
  #  us.zones
  #  us.zone_info
  class Country
    include Comparable
    
    # Defined countries.
    @@countries = {}
    
    # Whether the countries index has been loaded yet.
    @@index_loaded = false
    
    # Gets a Country by its ISO 3166 code. Raises an InvalidCountryCode 
    # exception if it couldn't be found.
    def self.get(identifier)
      instance = @@countries[identifier]
      
      unless instance
        load_index
        info = Indexes::Countries.countries[identifier]        
        raise InvalidCountryCode.new, 'Invalid identifier' unless info
        instance = Country.new(info)
        @@countries[identifier] = instance
      end      
      
      instance        
    end
    
    # If identifier is a CountryInfo object, initializes the Country instance, 
    # otherwise calls get(identifier).
    def self.new(identifier)      
      if identifier.kind_of?(CountryInfo)
        instance = super()
        instance.send :setup, identifier
        instance
      else
        get(identifier)
      end
    end
    
    # Returns an Array of all the valid country codes.
    def self.all_codes
      load_index
      Indexes::Countries.countries.keys
    end
    
    # Returns an Array of all the defined Countries.
    def self.all
      load_index
      Indexes::Countries.countries.keys.collect {|code| get(code)}
    end       
    
    # The ISO 3166 country code.
    def code
      @info.code
    end
    
    # The name of the country.
    def name
      @info.name
    end
    
    # Alias for name.
    def to_s
      name
    end
    
    # Returns internal object state as a programmer-readable string.
    def inspect
      "#<#{self.class}: #{@info.code}>"
    end
    
    # Returns a frozen array of all the zone identifiers for the country. These
    # are in an order that
    #   (1) makes some geographical sense, and
    #   (2) puts the most populous zones first, where that does not contradict (1).
    def zone_identifiers
      @info.zone_identifiers
    end
    alias zone_names zone_identifiers
    
    # An array of all the Timezones for this country. Returns TimezoneProxy
    # objects to avoid the overhead of loading Timezone definitions until
    # a conversion is actually required. The Timezones are returned in an order
    # that
    #   (1) makes some geographical sense, and
    #   (2) puts the most populous zones first, where that does not contradict (1).
    def zones
      zone_identifiers.collect {|id|
        Timezone.get_proxy(id)        
      }
    end
    
    # Returns a frozen array of all the timezones for the for the country as
    # CountryTimezone instances (containing extra information about each zone). 
    # These are in an order that
    #   (1) makes some geographical sense, and
    #   (2) puts the most populous zones first, where that does not contradict (1).
    def zone_info
      @info.zones
    end
        
    # Compare two Countries based on their code. Returns -1 if c is less
    # than self, 0 if c is equal to self and +1 if c is greater than self.
    def <=>(c)
      code <=> c.code
    end
    
    # Returns true if and only if the code of c is equal to the code of this
    # Country.
    def eql?(c)
      self == c
    end
    
    # Returns a hash value for this Country.
    def hash
      code.hash
    end
    
    # Dumps this Country for marshalling.
    def _dump(limit)
      code
    end
    
    # Loads a marshalled Country.
    def self._load(data)
      Country.get(data)
    end
    
    private
      # Loads in the index of countries if it hasn't already been loaded.
      def self.load_index
        unless @@index_loaded
          require 'tzinfo/indexes/countries'
          @@index_loaded = true
        end        
      end     
      
      # Called by Country.new to initialize a new Country instance. The info
      # parameter is a CountryInfo that defines the country.
      def setup(info)
        @info = info        
      end
  end 
end

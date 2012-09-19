#--
# Copyright (c) 2006-2010 Philip Ross
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
  # The country index file includes CountryIndexDefinition which provides
  # a country method used to define each country in the index.
  module CountryIndexDefinition #:nodoc:
    def self.append_features(base)
      super
      base.extend(ClassMethods)
      base.instance_eval { @countries = {} }
    end
    
    module ClassMethods #:nodoc:
      # Defines a country with an ISO 3166 country code, name and block. The
      # block will be evaluated to obtain all the timezones for the country.
      # Calls Country.country_defined with the definition of each country.
      def country(code, name, &block)
        @countries[code] = CountryInfo.new(code, name, &block)      
      end
      
      # Returns a frozen hash of all the countries that have been defined in
      # the index.
      def countries
        @countries.freeze
      end
    end
  end
end

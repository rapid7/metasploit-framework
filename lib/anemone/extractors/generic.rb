require 'uri'

class Anemone::Extractors::Generic < Anemone::Extractors::Base

  def run
    URI.extract( doc.to_s, %w(http https) ).map do |u|
      #
      # This extractor needs to be a tiny bit intelligent because
      # due to its generic nature it'll inevitably match some garbage.
      #
      # For example, if some JS code contains:
      #
      #	var = 'http://blah.com?id=1'
      #
      # or
      #
      #	var = { 'http://blah.com?id=1', 1 }
      #
      #
      # The URI.extract call will match:
      #
      #	http://blah.com?id=1'
      #
      # and
      #
      #	http://blah.com?id=1',
      #
      # respectively.
      #
      if !includes_quotes?( u )
        u
      else
        if html.include?( "'#{u}" )
          u.split( '\'' ).first
        elsif html.include?( "\"#{u}" )
          u.split( '"' ).first
        else
          u
        end
      end
    end
  rescue
    []
  end

  def includes_quotes?( url )
    url.include?( '\'' ) || url.include?( '"' )
  end

end

class Anemone::Extractors::MetaRefresh < Anemone::Extractors::Base

  def run
    doc.search( "//meta[@http-equiv='refresh']" ).map do |url|
      begin
        _, url = url['content'].split( ';', 2 )
        next if !url
        unquote( url.split( '=', 2 ).last )
      rescue
        next
      end
    end
  rescue
    nil
  end

  def unquote( str )
    [ '\'', '"' ].each do |q|
      return str[1...-1] if str.start_with?( q ) && str.end_with?( q )
    end
    str
  end

end

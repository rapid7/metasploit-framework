class Anemone::Extractors::Scripts < Anemone::Extractors::Base

  def run
    doc.search( '//script[@src]' ).map { |a| a['src'] }
  end

end

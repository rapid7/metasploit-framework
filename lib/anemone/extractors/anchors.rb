class Anemone::Extractors::Anchors < Anemone::Extractors::Base

  def run
    doc.search( '//a[@href]' ).map { |a| a['href'] }
  end

end

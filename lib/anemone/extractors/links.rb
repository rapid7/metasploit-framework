class Anemone::Extractors::Links < Anemone::Extractors::Base

  def run
    doc.search( "//link[@href]" ).map { |a| a['href'] }
  end

end

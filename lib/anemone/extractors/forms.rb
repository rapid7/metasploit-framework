class Anemone::Extractors::Forms < Anemone::Extractors::Base

  def run
    doc.search( '//form[@action]' ).map { |a| a['action'] }
  end
  
end

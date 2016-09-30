class Anemone::Extractors::Frames < Anemone::Extractors::Base

  def run
    doc.css( 'frame', 'iframe' ).map { |a| a.attributes['src'].content rescue next }
  end

end

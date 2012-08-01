class Anemone::Extractors::Frames

    def run( doc )
        doc.css( 'frame', 'iframe' ).map { |a| a.attributes['src'].content rescue next }
    end

end

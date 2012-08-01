class Anemone::Extractors::Anchors

    def run( doc )
        doc.search( '//a[@href]' ).map { |a| a['href'] }
    end

end

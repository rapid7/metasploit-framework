class Anemone::Extractors::Scripts

    def run( doc )
        doc.search( '//script[@src]' ).map { |a| a['src'] }
    end

end

class Anemone::Extractors::Forms

    def run( doc )
        doc.search( '//form[@action]' ).map { |a| a['action'] }
    end

end

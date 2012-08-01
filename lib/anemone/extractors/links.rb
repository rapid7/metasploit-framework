class Anemone::Extractors::Links

    def run( doc )
        doc.search( "//link[@href]" ).map { |a| a['href'] }
    end

end

class Anemone::Extractors::Dirbuster < Anemone::Extractors::Base

  def run
    return [] if page.code.to_i != 200

    @@dirs ||= nil

    return @@dirs if @@dirs
    @@dirs = IO.read( File.dirname( __FILE__ ) + '/dirbuster/directories' ).split( "\n" )
  end
  
end

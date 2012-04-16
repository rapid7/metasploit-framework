module CodeRay
module Scanners

  load :html

  # Scanner for XML.
  #
  # Currently this is the same scanner as Scanners::HTML.
  class XML < HTML

    register_for :xml
    file_extension 'xml'
    
  end

end
end

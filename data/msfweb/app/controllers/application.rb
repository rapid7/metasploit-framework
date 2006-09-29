# Filters added to this controller will be run for all controllers in the application.
# Likewise, all the methods added will be available for all controllers.
class ApplicationController < ActionController::Base

  def search_modules(mlist, terms)
    res = {}
    
    unless terms
      return nil
    end
    
    # Match search terms
    mlist.each do |m|
	  
      if (terms.length == 0)
        res[m.name]=m
        next
      end
    
      if (m.name.downcase.index(terms.downcase))
        res[m.name]=m
        next
      end

      if (m.description.downcase.index(terms.downcase))
        res[m.name]=m
        next
      end
            
    end
	
    # Sort the modules by name
    list = []
    res.keys.sort.each do |n|
      list << res[n]
    end
      
    list
  end
  
end

# Copyright (c) 2006 L.M.H <lmh@info-pull.com>
# All Rights Reserved.

# Methods added to this helper will be available to all templates in the application.
module ApplicationHelper

  # Updates a node (ex. div container) by it's ID with content from
  # specified URL.
  def dojo_node_update(node_id, target_url)
   return "dojo.io.updateNode('"+ node_id +"',{url:'"+ target_url +"'})"
  end
  
end

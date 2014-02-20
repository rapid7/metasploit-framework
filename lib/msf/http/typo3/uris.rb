# -*- coding: binary -*-
module Msf::HTTP::Typo3::URIs

  # Returns the Typo3 Login URL
  #
  # @return [String] Typo3 Login URL
  def typo3_url_login
    normalize_uri(target_uri.path, 'typo3', 'index.php')
  end

  # Returns the Typo3 backend URL
  #
  # @return [String] Typo3 Backend URL
  def typo3_url_backend
    normalize_uri(target_uri.path, 'typo3', 'backend.php')
  end

end

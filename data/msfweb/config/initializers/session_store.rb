# Be sure to restart your server when you modify this file.

# Your secret key for verifying cookie session data integrity.
# If you change this key, all old sessions will become invalid!
# Make sure the secret is at least 30 characters and all random, 
# no regular words or you'll be exposed to dictionary attacks.
ActionController::Base.session = {
  :key         => '_msfweb_session',
  :secret      => 'f604cddb9e95fe02234d1ddb08f73f3c64e672998ff743cf80171429d6c985cafbb39698de70ee7f626ebc5aa9afdcd23d9da562fa70d942e83b6ba49e0046c4'
}

# Use the database for sessions instead of the cookie-based default,
# which shouldn't be used to store highly confidential information
# (create the session table with "rake db:sessions:create")
# ActionController::Base.session_store = :active_record_store

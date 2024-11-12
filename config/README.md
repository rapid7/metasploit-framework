# Metasploit Framework Config Folder

Contains various files that help configure Metasploit. Most files here you'll never have to deal with, though
`database.yml.example` might be useful for those looking to configure their database, and `openssl.conf`
might be helpful for those trying to troubleshoot OpenSSL issues in Metasploit.

> [!IMPORTANT]
> Because the behavior of Ruby on Rails changes between versions,
> and code needs to be considered thread-safe when dealing with Ruby on Rails,
> we ensure that the `reconnect: true` property is configured for our database
> connection. This allows the console/framework to reconnect when a thread messes
> up the connection pool.

##
# $Id$
#
# This file maps parsers for autoload
##

module Rex
module Parser
	# General parsers
	autoload :Arguments, 'rex/parser/arguments'
	autoload :Ini,       'rex/parser/ini'

	# Data import parsers
	autoload :NmapXMLStreamParser,       'rex/parser/nmap_xml'
	autoload :NexposeXMLStreamParser,    'rex/parser/nexpose_xml'
	autoload :RetinaXMLStreamParser,     'rex/parser/retina_xml'
	autoload :NetSparkerXMLStreamParser, 'rex/parser/netsparker_xml'
	autoload :NessusXMLStreamParser,     'rex/parser/nessus_xml'
	autoload :IP360XMLStreamParser,      'rex/parser/ip360_xml'
	autoload :IP360ASPLXMLStreamParser,  'rex/parser/ip360_aspl_xml'
	autoload :AppleBackupManifestDB,     'rex/parser/apple_backup_manifestdb'
end
end

# Based on 'relative2' in https://github.com/jwilk/path-traversal-samples,
# but create the local `tmp` folder before adding the symlink. Otherwise
# we may bail out before we get to trying to create the file.
all: relative1.zip
relative1.zip:
	rm -f $(@)
	mkdir -p -m 755 tmp/tmp
	umask 022 && echo moo > moo
	cd tmp && zip -X ../$(@) tmp tmp/../../moo
	rm -rf tmp moo

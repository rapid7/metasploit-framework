all = example.rb example.php example.c example.java example.scm example.pl example.js

all:  $(all)

example.rb:   example.eruby
	erubis --pi -l ruby example.eruby > example.rb


example.php:  example.ephp
	erubis --pi -l php example.ephp > example.php

example.c:    example.ec
	erubis --pi -bl c example.ec > example.c

example.java: example.ejava
	erubis --pi -bl java example.ejava > example.java

example.scm:  example.escheme
	erubis --pi -l scheme --func=display example.escheme > example.scm
#	erubis --pi -l scheme example.escheme > example.scm

example.pl:   example.eperl
	erubis --pi -l perl example.eperl > example.pl

example.js:   example.ejs
	erubis --pi -l javascript example.ejs > example.js


###----------

src = example.eruby example.ephp example.ec example.ejava example.escheme example.eperl example.ejs Makefile

clean:
	rm -f `ruby -e 'puts(Dir.glob("*.*") - %w[$(src)])'`
#	rm -f $(all)

compile:  example.bin example.class

example.bin:   example.c
	cc -o example.bin example.c

example.class:  example.java
	jikes example.java

output:  $(all) example.bin example.class
	erubis --pi example.eruby > example.ruby.result
	#ruby example.rb > example.ruby.result
	php example.php > example.php.result
	./example.bin '<aaa>' 'b&b' '"ccc"' > example.c.result
	java example > example.java.result
	gosh example.scm > example.scm.result
	#guile example.scm > example.scm.result
	perl example.pl > example.pl.result


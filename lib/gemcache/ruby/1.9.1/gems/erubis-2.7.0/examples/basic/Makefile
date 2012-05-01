all = example.rb example.php example.c example.cpp example.java example.scm example.pl example.js

all:  $(all)

example.rb:   example.eruby
	erubis -l ruby example.eruby > example.rb


example.php:  example.ephp
	erubis -l php example.ephp > example.php

example.c:    example.ec
	erubis -bl c example.ec > example.c

example.cpp:    example.ecpp
	erubis -bl cpp example.ecpp > example.cpp

example.java: example.ejava
	erubis -bl java example.ejava > example.java

example.scm:  example.escheme
	erubis -l scheme --func=display example.escheme > example.scm
#	erubis -l scheme example.escheme > example.scm

example.pl:   example.eperl
	erubis -l perl example.eperl > example.pl

example.js:   example.ejs
	erubis -l javascript example.ejs > example.js


###----------

src = example.eruby example.ephp example.ec example.ecpp example.ejava example.escheme example.eperl example.ejs Makefile

clean:
	rm -f `ruby -e 'puts(Dir.glob("*.*") - %w[$(src)])'`
#	rm -f $(all)

compile:  example.bin example.class

example.bin:   example.c
	cc -o example.bin example.c
	g++ -o example.bin2 example.cpp

example.class:  example.java
	jikes example.java

output:  $(all) example.bin example.class
	erubis example.eruby > example.ruby.out
	php example.php > example.php.out
	./example.bin '<aaa>' 'b&b' '"ccc"' > example.c.out
	./example.bin2 '<aaa>' 'b&b' '"ccc"' > example.cpp.out
	java example > example.javexample.bin
	gosh example.scm > example.scm.out
#	guile example.scm > example.scm.out
	perl example.pl > example.pl.out


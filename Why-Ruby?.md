The following was written somewhere around 2005.

During the development of the framework, the one recurring question that the Metasploit staff was continually asked was why Ruby was selected as the programming language. To avoid having to answer this question on an individual basis, the authors have opted for explaining their reasons in this document.

The Ruby programming language was selected over other choices, such as python, perl, and C++ for quite a few reasons. The first (and primary) reason that Ruby was selected was because it was a language that the Metasploit staff enjoyed writing in. After spending time analyzing other languages and factoring in past experiences, the Ruby programming language was found to offer both a simple and powerful approach to an interpreted language. The degree of introspection and the object-oriented aspects provided by Ruby were something that fit very nicely with some of the requirements of the framework. The framework's need for automated class construction for code re-use was a key factor in the decision making process, and it was one of the things that perl was not very well suited to offer. On top of this, the syntax is incredibly simplistic and provides the same level of language features that other more accepted languages have, like perl.

The second reason Ruby was selected was because of its platform independent support for threading. While a number of limitations have been encountered during the development of the framework under this model, the Metasploit staff has observed a marked performance and usability improvement over the 2.x branch. Future versions of Ruby (the 1.9 series) will back the existing threading API with native threads for the operating system the interpreter is compiled against which will solve a number of existing issues with the current implementation (such as permitting the use of blocking operations). In the meantime, the existing threading model has been found to be far superior when compared to a conventional forking model, especially on platforms that lack a native fork implementation like Windows.

Another reason that Ruby was selected was because of the supported existence of a native interpreter for the Windows platform. While perl has a cygwin version and an ActiveState version, both are plagued by usability problems. The fact that the Ruby interpreter can be compiled and executed natively on Windows drastically improves performance. Furthermore, the interpreter is also very small and can be easily modified in the event that there is a bug.

The Python programming language was also a language candidate. The reason the Metasploit staff opted for Ruby instead of python was for a few different reasons. The primary reason is a general distaste for some of the syntactical annoyances forced by python, such as block-indention. While many would argue the benefits of such an approach, some members of the Metasploit staff find it to be an unnecessary restriction. Other issues with Python center around limitations in parent class method calling and backward compatibility of interpreters.

The C/C++ programming languages were also very seriously considered, but in the end it was obvious that attempting to deploy a portable and usable framework in a non-interpreted language was something that would not be feasible.

Furthermore, the development time-line for this language selection would most likely be much longer. Even though the 2.x branch of the framework has been quite successful, the Metasploit staff encountered a number of limitations and annoyances with perl's object-oriented programming model, or lack thereof. The fact that the perl interpreter is part of the default install on many distributions is not something that the Metasploit staff felt was worth detouring the language selection. 

In the end, it all came down to selecting a language that was enjoyed by the people who contribute the most to the framework, and that language ended up being Ruby.

# Resource

* https://github.com/rapid7/metasploit-framework/blob/master/documentation/developers_guide.pdf
* https://dev.metasploit.com/pipermail/framework/2006-October/001325.html
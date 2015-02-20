# -*- coding: binary -*-

require 'rex/zip/archive'

module Rex
module Zip

#
# A Jar is a zip archive containing Java class files and a MANIFEST.MF listing
# those classes.  Several variations exist based on the same idea of class
# files inside a zip, most notably:
# - WAR files store XML files, Java classes, JSPs and other stuff for
#   servlet-based webservers (e.g.: Tomcat and Glassfish)
# - APK files are Android Package files
#
class Jar < Archive
  attr_accessor :manifest
  # @!attribute [rw] substitutions
  #   The substitutions to apply when randomizing. Randomization is designed to
  #   be used in packages and/or classes names.
  #
  #   @return [Hash]
  attr_accessor :substitutions

  def initialize
    @substitutions = {}
    super
  end

  #
  # Create a MANIFEST.MF file based on the current Archive#entries.
  #
  # See http://download.oracle.com/javase/1.4.2/docs/guide/jar/jar.html for
  # some explanation of the format.
  #
  # Example MANIFEST.MF
  #   Manifest-Version: 1.0
  #   Main-Class: metasploit.Payload
  #
  #   Name: metasploit.dat
  #   SHA1-Digest: WJ7cUVYUryLKfQFmH80/ADfKmwM=
  #
  #   Name: metasploit/Payload.class
  #   SHA1-Digest: KbAIMttBcLp1zCewA2ERYkcnRU8=
  #
  # The SHA1-Digest lines are optional unless the jar is signed (see #sign).
  #
  def build_manifest(opts={})
    main_class = (opts[:main_class] ? randomize(opts[:main_class]) : nil)
    app_name = (opts[:app_name] ? randomize(opts[:main_class]) : nil)
    existing_manifest = nil

    @manifest =  "Manifest-Version: 1.0\r\n"
    @manifest << "Main-Class: #{main_class}\r\n" if main_class
    @manifest << "Application-Name: #{app_name}\r\n" if app_name
    @manifest << "Permissions: all-permissions\r\n"
    @manifest << "\r\n"
    @entries.each { |e|
      next if e.name =~ %r|/$|
      if e.name == "META-INF/MANIFEST.MF"
        existing_manifest = e
        next
      end
      #next unless e.name =~ /\.class$/
      @manifest << "Name: #{e.name}\r\n"
      #@manifest << "SHA1-Digest: #{Digest::SHA1.base64digest(e.data)}\r\n"
      @manifest << "\r\n"
    }
    if existing_manifest
      existing_manifest.data = @manifest
    else
      add_file("META-INF/", '')
      add_file("META-INF/MANIFEST.MF", @manifest)
    end
  end

  def to_s
    pack
  end

  #
  # Length of the *compressed* blob
  #
  def length
    pack.length
  end

  #
  # Add multiple files from an array
  #
  # +files+ should be structured like so:
  #   [
  #     [ "path", "to", "file1" ],
  #     [ "path", "to", "file2" ]
  #   ]
  # and +path+ should be the location on the file system to find the files to
  # add.  +base_dir+ will be prepended to the path inside the jar.
  #
  # Example:
  #   war = Rex::Zip::Jar.new
  #   war.add_file("WEB-INF/", '')
  #   war.add_file("WEB-INF/web.xml", web_xml)
  #   war.add_file("WEB-INF/classes/", '')
  #   files = [
  #     [ "servlet", "examples", "HelloWorld.class" ],
  #     [ "Foo.class" ],
  #     [ "servlet", "Bar.class" ],
  #   ]
  #   war.add_files(files, "./class_files/", "WEB-INF/classes/")
  #
  # The above code would create a jar with the following structure from files
  # found in ./class_files/ :
  #
  #   +- WEB-INF/
  #     +- web.xml
  #     +- classes/
  #       +- Foo.class
  #       +- servlet/
  #         +- Bar.class
  #         +- examples/
  #           +- HelloWorld.class
  #
  def add_files(files, path, base_dir="")
    files.each do |file|
      # Add all of the subdirectories if they don't already exist
      1.upto(file.length - 1) do |idx|
        full = base_dir + file[0,idx].join("/") + "/"
        if !(entries.map{|e|e.name}.include?(full))
          add_file(full, '')
        end
      end
      # Now add the actual file, grabbing data from the filesystem
      fd = File.open(File.join( path, file ), "rb")
      data = fd.read(fd.stat.size)
      fd.close
      add_file(base_dir + file.join("/"), data)
    end
  end

  #
  # Add a signature to this jar given a +key+ and a +cert+.  +cert+ should be
  # an instance of OpenSSL::X509::Certificate and +key+ is expected to be an
  # instance of one of OpenSSL::PKey::DSA or OpenSSL::PKey::RSA.
  #
  # This method aims to create signature files compatible with the jarsigner
  # tool destributed with the JDK and any JVM should accept the resulting
  # jar.
  #
  # === Signature contents
  # Modifies the META-INF/MANIFEST.MF entry adding SHA1-Digest attributes in
  # each Name section.  The signature consists of two files, a .SF and a .DSA
  # (or .RSA if signing with an RSA key).  The .SF file is similar to the
  # manifest with Name sections but the SHA1-Digest is not optional.  The
  # difference is in what gets hashed for the SHA1-Digest line -- in the
  # manifest, it is the file's contents, in the .SF, it is the file's section
  # in the manifest (including trailing newline!).  The .DSA/.RSA file is a
  # PKCS7 signature of the .SF file contents.
  #
  # === Links
  # A short description of the format:
  # http://download.oracle.com/javase/1.4.2/docs/guide/jar/jar.html#Signed%20JAR%20File
  #
  # Some info on importing a private key into a keystore which is not
  # directly supported by keytool for some unfathomable reason
  # http://www.agentbob.info/agentbob/79-AB.html
  #
  def sign(key, cert, ca_certs=nil)
    m = self.entries.find { |e| e.name == "META-INF/MANIFEST.MF" }
    raise RuntimeError.new("Jar has no manifest") unless m

    ca_certs ||= [ cert ]

    new_manifest = ''
    sigdata =  "Signature-Version: 1.0\r\n"
    sigdata << "Created-By: 1.6.0_18 (Sun Microsystems Inc.)\r\n"
    sigdata << "\r\n"

    # Grab the sections of the manifest
    files = m.data.split(/\r?\n\r?\n/)
    if files[0] =~ /Manifest-Version/
      # keep the header as is
      new_manifest << files[0]
      new_manifest << "\r\n\r\n"
      files = files[1,files.length]
    end

    # The file sections should now look like this:
    #  "Name: metasploit/Payload.class\r\nSHA1-Digest: KbAIMttBcLp1zCewA2ERYkcnRU8=\r\n\r\n"
    files.each do |f|
      next unless f =~ /Name: (.*)/
      name = $1
      e = self.entries.find { |e| e.name == name }
      if e
        digest = OpenSSL::Digest::SHA1.digest(e.data)
        manifest_section =  "Name: #{name}\r\n"
        manifest_section << "SHA1-Digest: #{[digest].pack('m').strip}\r\n"
        manifest_section << "\r\n"

        manifest_digest = OpenSSL::Digest::SHA1.digest(manifest_section)

        sigdata << "Name: #{name}\r\n"
        sigdata << "SHA1-Digest: #{[manifest_digest].pack('m')}\r\n"
        new_manifest << manifest_section
      end
    end

    # Now overwrite with the new manifest
    m.data = new_manifest

    flags = 0
    flags |= OpenSSL::PKCS7::BINARY
    flags |= OpenSSL::PKCS7::DETACHED
    # SMIME and ATTRs are technically valid in the signature but they
    # both screw up the java verifier, so don't include them.
    flags |= OpenSSL::PKCS7::NOSMIMECAP
    flags |= OpenSSL::PKCS7::NOATTR

    signature = OpenSSL::PKCS7.sign(cert, key, sigdata, ca_certs, flags)
    sigalg = case key
      when OpenSSL::PKey::RSA; "RSA"
      when OpenSSL::PKey::DSA; "DSA"
      # Don't really know what to do if it's not DSA or RSA.  Can
      # OpenSSL::PKCS7 actually sign stuff with it in that case?
      # Regardless, the java spec says signatures can only be RSA,
      # DSA, or PGP, so just assume it's PGP and hope for the best
      else; "PGP"
      end

    # SIGNFILE is the default name in documentation.  MYKEY is probably
    # more common, though because that's what keytool defaults to.  We
    # can probably randomize this with no ill effects.
    add_file("META-INF/SIGNFILE.SF", sigdata)
    add_file("META-INF/SIGNFILE.#{sigalg}", signature.to_der)

    return true
  end

  # Adds a file to the JAR, randomizing the file name
  # and the contents.
  #
  # @see Rex::Zip::Archive#add_file
  def add_file(fname, fdata=nil, xtra=nil, comment=nil)
    super(randomize(fname), randomize(fdata), xtra, comment)
  end

  # Adds a substitution to have into account when randomizing. Substitutions
  # must be added immediately after {#initialize}.
  #
  # @param str [String] String to substitute. It's designed to randomize
  #   class and/or package names.
  # @param bad [String] String containing bad characters to avoid when
  #   applying substitutions.
  # @return [String] The substitution which will be used when randomizing.
  def add_sub(str, bad = '')
    if @substitutions.key?(str)
      return @substitutions[str]
    end

    @substitutions[str] = Rex::Text.rand_text_alpha(str.length, bad)
  end

  # Randomizes an input by applying the `substitutions` available.
  #
  # @param str [String] String to randomize.
  # @return [String] The input `str` with all the possible `substitutions`
  #   applied.
  def randomize(str)
    return str if str.nil?

    random = str

    @substitutions.each do |orig, subs|
      random = str.gsub(orig, subs)
    end

    random
  end

end

end
end


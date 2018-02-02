# Metasploit's 2018 Roadmap

In 2017, we published our first open roadmap for Metasploit development. How did we do? For achievements:

 * The Metasploit data model backend: we did a lot of design work on this, and got a couple of initial Proof-of-Concept project built. You can see a video of it here: https://www.youtube.com/edit?o=U&video_id=hvuy6A-ie1g. In the mean time, we started merging parts of the main development branch 

 * The first pass of external session handling landed with the metasploit-proxy project. 

 * Independent modules that run in isolation _did_ land, along with a hand full of new modules demonstrating the advantages of the design, including multi-language support.

 * The ruby_smb project made a lot of progress, with support incorporated into several existing modules. Full client-side support is also available for testing now.

 * Native iOS and macOS support landed, along with many new IoT and router exploits.

 * Meterpreter shrank almost 4x thanks to the new cryptTLV packet obfuscation support, and the removal of OpenSSL.
Index: lib/rex/pescan/analyze.rb
===================================================================
--- lib/rex/pescan/analyze.rb	(revision 5155)
+++ lib/rex/pescan/analyze.rb	(working copy)
@@ -265,12 +265,28 @@
 				next if section.name == ".data"
 				next if section.name == ".reloc"
 				
-				data = section.read(0, section.size)
-				buff = [ 0x01, pe.rva_to_vma( section.base_rva ), data.length, data].pack("CNNA*")
+				offset = 0
+				while offset < section.size
+					byte = section.read(offset, 1)[0]
+					if byte != 0
+						chunkbase = pe.rva_to_vma( section.base_rva) + offset
+						data = ''
+						while byte != 0
+							data << byte
+							offset += 1
+							byte = 0
+							byte = section.read(offset, 1)[0] if offset < section.size
+						end
+						buff = nil
+						buff = [ 0x01, chunkbase, data.length, data].pack("CNNA*") if data.length > 0
 				
-				fd.write(buff)
+						fd.write(buff) if buff
+					end
+					offset += 1
+				end
+
+			end
 				
-			end
 			
 			fd.close
 		end

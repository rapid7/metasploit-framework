# -*- coding: binary -*-
module Rex
  module Parser
    ###
    #
    # This class parses the contents of an NTFS partition file.
    # Author : Danil Bazin <danil.bazin[at]hsc.fr> @danilbaz
    #
    ###
    class NTFS
      #
      # Initialize the NTFS class with an already open file handler
      #
      DATA_ATTRIBUTE_ID = 128
      INDEX_ROOT_ID = 144
      INDEX_ALLOCATION_ID = 160
      def initialize(file_handler)
        @file_handler = file_handler
        data = @file_handler.read(4096)
        # Boot sector reading
        @bytes_per_sector = data[11, 2].unpack('v')[0]
        @sector_per_cluster = data[13].unpack('C')[0]
        @cluster_per_mft_record = data[64].unpack('c')[0]
        if @cluster_per_mft_record < 0
          @bytes_per_mft_record = 2**(-@cluster_per_mft_record)
          @cluster_per_mft_record = @bytes_per_mft_record.to_f / @bytes_per_sector / @sector_per_cluster
        else
          @bytes_per_mft_record = @bytes_per_sector * @sector_per_cluster * @cluster_per_mft_record
        end
        @bytes_per_cluster = @sector_per_cluster * @bytes_per_sector
        @mft_logical_cluster_number = data[48, 8].unpack('Q<')[0]
        @mft_offset = @mft_logical_cluster_number * @sector_per_cluster * @bytes_per_sector
        @file_handler.seek(@mft_offset)
        @mft = @file_handler.read(@bytes_per_mft_record)
      end

      #
      # Gather the MFT entry corresponding to his number
      #
      def mft_record_from_mft_num(mft_num)
        mft_num_offset = mft_num * @cluster_per_mft_record
        mft_data_attribute = mft_record_attribute(@mft)[DATA_ATTRIBUTE_ID]['data']
        cluster_from_attribute_non_resident(mft_data_attribute, mft_num_offset, @bytes_per_mft_record)
      end

      #
      # Get the size of the file in the $FILENAME (64) attribute
      #
      def real_size_from_filenameattribute(attribute)
        filename_attribute = attribute
        filename_attribute[48, 8].unpack('Q<')[0]
      end

      #
      # Gather the name of the file from the $FILENAME (64) attribute
      #
      def filename_from_filenameattribute(attribute)
        filename_attribute = attribute
        length_of_name = filename_attribute[64].ord
        # uft16 *2
        d = ::Encoding::Converter.new('UTF-16LE', 'UTF-8')
        d.convert(filename_attribute[66, (length_of_name * 2)])
      end

      #
      # Get the file from the MFT number
      # The size must be gived because the $FILENAME attribute
      # in the MFT entry does not contain it
      # The file is in $DATA (128) Attribute
      #
      def file_content_from_mft_num(mft_num, size)
        mft_record = mft_record_from_mft_num(mft_num)
        attribute_list = mft_record_attribute(mft_record)
        if attribute_list[DATA_ATTRIBUTE_ID]['resident']
          return attribute_list[DATA_ATTRIBUTE_ID]['data']
        else
          data_attribute = attribute_list[DATA_ATTRIBUTE_ID]['data']
          return cluster_from_attribute_non_resident(data_attribute)[0, size]
        end
      end

      #
      # parse one index record and return the name, MFT number and size of the file
      #
      def parse_index(index_entry)
        res = {}
        filename_size = index_entry[10, 2].unpack('v')[0]
        filename_attribute = index_entry[16, filename_size]
        # Should be 8 bytes but it doesn't work
        # mft_offset =  index_entry[0.unpack('Q<',:8])[0]
        # work with 4 bytes
        mft_offset =  index_entry[0, 4].unpack('V')[0]
        res[filename_from_filenameattribute(filename_attribute)] = {
          'mft_offset' => mft_offset,
          'file_size' => real_size_from_filenameattribute(filename_attribute) }
        res
      end

      #
      # parse index_record in $INDEX_ROOT and recursively index_record in
      # INDEX_ALLOCATION
      #
      def parse_index_list(index_record, index_allocation_attribute)
        offset_index_entry_list = index_record[0, 4].unpack('V')[0]
        index_size =  index_record[offset_index_entry_list + 8, 2].unpack('v')[0]
        index_size_in_bytes = index_size * @bytes_per_cluster
        index_entry = index_record[offset_index_entry_list, index_size]
        res = {}
        while index_entry[12, 4].unpack('V')[0] & 2 != 2
          res.update(parse_index(index_entry))
          # if son
          if index_entry[12, 4].unpack('V')[0] & 1 == 1
            # should be 8 bytes length
            vcn =  index_entry[-8, 4].unpack('V')[0]
            vcn_in_bytes = vcn * @bytes_per_cluster
            res_son = parse_index_list(index_allocation_attribute[vcn_in_bytes + 24, index_size_in_bytes], index_allocation_attribute)
            res.update(res_son)
          end
          offset_index_entry_list += index_size
          index_size =  index_record[offset_index_entry_list + 8, 2].unpack('v')[0]
          index_size_in_bytes = index_size * @bytes_per_cluster
          index_entry = index_record [offset_index_entry_list, index_size]
        end
        # if son on the last
        if index_entry[12, 4].unpack('V')[0] & 1 == 1
          # should be 8 bytes length
          vcn =  index_entry[-8, 4].unpack('V')[0]
          vcn_in_bytes = vcn * @bytes_per_cluster
          res_son = parse_index_list(index_allocation_attribute[vcn_in_bytes + 24, index_size_in_bytes], index_allocation_attribute)
          res.update(res_son)
        end
        res
      end

      #
      # return the list of files in attribute directory and their MFT number and size
      #
      def index_list_from_attributes(attributes)
        index_root_attribute = attributes[INDEX_ROOT_ID]
        index_record = index_root_attribute[16, index_root_attribute.length - 16]
        if attributes.key?(INDEX_ALLOCATION_ID)
          return parse_index_list(index_record, attributes[INDEX_ALLOCATION_ID])
        else
          return parse_index_list(index_record, '')
        end
      end

      def cluster_from_attribute_non_resident(attribute, cluster_num = 0, size_max = ((2**31) - 1))
        lowvcn = attribute[16, 8].unpack('Q<')[0]
        highvcn = attribute[24, 8].unpack('Q<')[0]
        offset = attribute[32, 2].unpack('v')[0]
        real_size = attribute[48, 8].unpack('Q<')[0]
        attribut = ''
        run_list_num = lowvcn
        old_offset = 0
        while run_list_num <= highvcn
          first_runlist_byte = attribute[offset].ord
          run_offset_size = first_runlist_byte >> 4
          run_length_size = first_runlist_byte & 15
          run_length = attribute[offset + 1, run_length_size]
          run_length += "\x00" * (8 - run_length_size)
          run_length = run_length.unpack('Q<')[0]

          offset_run_offset = offset + 1 + run_length_size
          run_offset = attribute[offset_run_offset, run_offset_size]
          if run_offset[-1].ord & 128 == 128
            run_offset += "\xFF" * (8 - run_offset_size)
          else
            run_offset += "\x00" * (8 - run_offset_size)
          end
          run_offset = run_offset.unpack('q<')[0]
          #offset relative to previous offset
          run_offset += old_offset

          size_wanted = [run_length * @bytes_per_cluster, size_max - attribut.length].min
          if cluster_num + (size_max / @bytes_per_cluster) >= run_list_num && (cluster_num < run_length + run_list_num)
            run_list_offset_in_cluster = run_offset + [cluster_num - run_list_num, 0].max
            run_list_offset = (run_list_offset_in_cluster) * @bytes_per_cluster
            run_list_offset = run_list_offset.to_i
            @file_handler.seek(run_list_offset)

            data = ''
            while data.length < size_wanted
              # Use a 4Mb block size to avoid target memory consumption
              data << @file_handler.read([size_wanted - data.length, 2**22].min)
            end
            attribut << data
          end
          offset += run_offset_size + run_length_size + 1
          run_list_num += run_length
          old_offset = run_offset
        end
        attribut = attribut[0, real_size]
        attribut
      end

      #
      # return the attribute list from the MFT record
      # deal with resident and non resident attributes (but not $DATA due to performance issue)
      # if lazy = True, this function only gather essential non resident attributes
      # (INDEX_ALLOCATION). Non resident attributes can still be gathered later with
      # cluster_from_attribute_non_resident function.
      #
      def mft_record_attribute(mft_record, lazy=true)
        attribute_list_offset = mft_record[20, 2].unpack('C')[0]
        curs = attribute_list_offset
        attribute_identifier = mft_record[curs, 4].unpack('V')[0]
        res = {}
        while attribute_identifier != 0xFFFFFFFF
          # attribute_size=mft_record[curs + 4, 4].unpack('V')[0]
          # should be on 4 bytes but doesnt work
          attribute_size = mft_record[curs + 4, 2].unpack('v')[0]
          # resident
          if mft_record[curs + 8] == "\x00"
            content_size = mft_record[curs + 16, 4].unpack('V')[0]
            content_offset = mft_record[curs + 20, 2].unpack('v')[0]
            res[attribute_identifier] = mft_record[curs + content_offset, content_size]
          else
            # non resident
            if attribute_identifier == INDEX_ALLOCATION_ID or 
              (!lazy and attribute_identifier != DATA_ATTRIBUTE_ID)
              res[attribute_identifier] = cluster_from_attribute_non_resident(mft_record[curs, attribute_size])
            else 
              res[attribute_identifier] = mft_record[curs, attribute_size]
            end
          end
          if attribute_identifier == DATA_ATTRIBUTE_ID
            res[attribute_identifier] = {
              'data' => res[attribute_identifier],
              'resident' => mft_record[curs + 8] == "\x00" }
          end
          curs += attribute_size
          attribute_identifier = mft_record[curs, 4].unpack('V')[0]
        end
        res
      end

      #
      # return the file path in the NTFS partition
      #
      def file(path)
        repertory = mft_record_from_mft_num(5)
        index_entry = {}
        path.split('\\').each do |r|
          attributes = mft_record_attribute(repertory)
          index = index_list_from_attributes(attributes)
          unless index.key?(r)
            fail ArgumentError, 'File path does not exist', caller
          end
          index_entry = index[r]
          repertory = mft_record_from_mft_num(index_entry['mft_offset'])
        end
        file_content_from_mft_num(index_entry['mft_offset'], index_entry['file_size'])
      end
    end
  end
end

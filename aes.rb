class Aes
  RCON = ['01', '02', '04', '08', '10', '20', '40', '80', '1b', '36']

  S_BOX_HEX = [["63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"],
               ["ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"],
               ["b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"],
               ["04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"],
               ["09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"],
               ["53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"],
               ["d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"],
               ["51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"],
               ["cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"],
               ["60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"],
               ["e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"],
               ["e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"],
               ["ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"],
               ["70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"],
               ["e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"],
               ["8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"]]

  REVERSE_S_BOX_HEX = [["52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb"],
                       ["7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb"],
                       ["54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e"],
                       ["08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25"],
                       ["72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92"],
                       ["6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84"],
                       ["90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06"],
                       ["d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b"],
                       ["3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73"],
                       ["96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e"],
                       ["47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b"],
                       ["fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4"],
                       ["1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f"],
                       ["60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef"],
                       ["a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61"],
                       ["17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d"]]


  def initialize(key)
    key_length = key.length
    raise KeyError, "Key size #{key_length} is not supported" unless key_length == 16
    @key = key
    key_expansion
  end

  def self.generate_random_key
    o = [('a'..'z'), (0..9), ('A'..'Z')].map(&:to_a).flatten
    string = (0...16).map { o[rand(o.length)] }.join
    return string
  end

  def encrypt(plain_text)
    puts plain_text
    blocks = break_into_blocks(plain_text)
    puts blocks.inspect
    # convert_block_into_words(blocks.first)
    blocks = blocks.collect { |block| convert_block_into_words(block) }
    puts blocks.inspect

    output_cipher_blocks = []
    blocks.each_with_index do |block, index|
      puts "Block #{index + 1}------------------"
      puts "Input Block: #{block}"

      # First add round key before rounds
      key_words = @key_words[0..3]
      add_round_key_output = add_round_key(block, key_words)

      cipher_block = encrypt_rounds(add_round_key_output, 1)
      puts "Cipher Block: #{cipher_block.inspect}"

      output_cipher_blocks << cipher_block
    end

    puts 'Output cipher blocks -------------'
    puts output_cipher_blocks.inspect

    # ToDo: Create hex stream from hex blocks
    cipher_text = combine_hex_blocks(output_cipher_blocks)

    return cipher_text
  end

  def encrypt_rounds(input_block, round)
    # Substitute Bytes step
    round_substitute_output = input_block.collect { |word| substitue_bytes(word) }
    # puts round_substitute_output.inspect

    # Shift rows step
    round_shift_rows_output = shift_rows(round_substitute_output)
    # puts round_shift_rows_output.inspect

    if round < 10
      # Mix Columns step
      round_mix_column_ouput = mix_columns(round_shift_rows_output)
    else
      round_mix_column_ouput = round_shift_rows_output
    end

    # Add round key step
    key_words = @key_words[(round*4)..(round*4+3)]
    round_add_round_key_output = add_round_key(round_mix_column_ouput, key_words)
    # puts round_add_round_key_output.inspect

    if round == 10
      return round_add_round_key_output
    else
      return encrypt_rounds(round_add_round_key_output, round + 1)
    end
  end

  def break_into_blocks(text)
    blocks = text.scan(/.{1,16}/)
    last_block = blocks.last
    if last_block.length < 16
      last_block = last_block.ljust(16, '{')
      blocks.pop
      blocks << last_block
    end
  end

  def convert_block_into_words(block)
    hex_array = string_to_hex_array(block)
    # puts hex_array.inspect
    hex_block = hex_array.each_slice(4).to_a
    # puts hex_block.inspect
    return hex_block
  end

  # Add round key XOR operation
  def add_round_key(block, key_words)
    # bitwise XOR between input_text and key
    output_block = []
    block.zip(key_words).each do |hex_word, hex_key_word|
      xor_data = hex_word_xor(hex_word, hex_key_word)
      output_block << xor_data
    end
    return output_block
  end

  # Replace bytes using S Box
  def substitue_bytes(hex_word)
    new_hex_word = []

    hex_word.each do |hex_byte|
      x, y = hex_byte.split('').map { |e| hex_to_int(e) }
      new_hex_word << S_BOX_HEX[x][y]
    end

    return new_hex_word
  end

  def shift_rows(block)
    output_block = []
    block.each_with_index do |word, index|
      if index > 0
        output_word = word.rotate(index)
      else
        output_word = word
      end
      output_block << output_word
    end

    return output_block
  end

  def mix_columns(block)


    return block
  end

  def combine_hex_blocks(blocks)
    hex_array = blocks.flatten
    # puts hex_array.inspect
    hex_array = hex_array.map{|hex_byte| "0x#{hex_byte}" }
    # puts hex_array.inspect
    return hex_array.join('')
  end

  def decrypt(cipher_text)
    puts cipher_text
    blocks = break_cipher_texts_to_block(cipher_text)
    puts blocks.inspect

    output_plain_text_blocks = []

    blocks.each_with_index do |block, index|
      puts "Block #{index + 1}------------------"
      puts "Input Block: #{block}"

      # First add round key before rounds
      key_words = @key_words[40..43]
      add_round_key_output = add_round_key(block, key_words)

      plain_text_block = decrypt_rounds(add_round_key_output, 1)
      puts "Plain Text Block: #{plain_text_block.inspect}"

      output_plain_text_blocks << plain_text_block
    end

    puts 'Output cipher blocks -------------'
    puts output_plain_text_blocks.inspect

    # Combine Plain Text blocks
    plain_text = combine_plain_text_blocks(output_plain_text_blocks)

    return plain_text
  end

  def break_cipher_texts_to_block(cipher_text)
    hex_array = cipher_text.split('0x').drop(1)
    blocks = hex_array.each_slice(16).to_a
    blocks = blocks.collect{|block| block.each_slice(4).to_a }
    # puts blocks.inspect
    return blocks
  end

  def decrypt_rounds(input_block, round)
    output_block = []

    # Shift rows step
    round_shift_rows_output = inverse_shift_rows(input_block)
    # puts round_shift_rows_output.inspect

    # Substitute Bytes step
    round_substitute_output = round_shift_rows_output.collect { |word| substitue_bytes(word) }
    # puts round_substitute_output.inspect

    # Add round key step
    key_words = @key_words[(round*4)..(round*4+3)]
    round_add_round_key_output = add_round_key(round_substitute_output, key_words)
    # puts round_add_round_key_output.inspect

    if round < 10
      # Mix Columns step
      round_mix_column_ouput = mix_columns(round_add_round_key_output)
    else
      round_mix_column_ouput = round_add_round_key_output
    end

    if round == 10
      return round_mix_column_ouput
    else
      return decrypt_rounds(round_mix_column_ouput, round + 1)
    end
  end

  def combine_plain_text_blocks(blocks)
    hex_array = blocks.flatten
    # puts hex_array.inspect
    return hex_array_to_string(hex_array)
  end

  def inverse_shift_rows(block)
    output_block = []
    block.each_with_index do |word, index|
      if index > 0
        output_word = word.rotate(index)
      else
        output_word = word
      end
      output_block << output_word
    end

    return output_block
  end

  def key_expansion
    puts "Original Key: #{@key}"
    hex_array = string_to_hex_array(@key)
    puts "Key converted to Hex: #{hex_array.inspect}"

    @key_words = []
    hex_array.each_slice(4) { |a| @key_words << a }

    (4..43).each do |i|
      temp = @key_words[i-1]
      temp = hex_word_xor(sub_hex_word(rot_hex_word(temp)), rcon_hex_word(i/4)) if (i % 4 == 0)
      @key_words[i] = hex_word_xor(@key_words[i-4], temp)
    end

    puts "Expanded Key: #{@key_words.inspect}"
  end

  def sub_hex_word(hex_word)
    # Substitue bytes using S Box
    return substitue_bytes(hex_word)
  end

  def rot_hex_word(hex_word)
    # one-byte circular left shift on a word
    return hex_word.rotate(1)
  end

  def rcon_hex_word(index)
    rc = RCON[index-1]
    rcon = [rc, '00', '00', '00']
    return rcon
  end

  def hex_word_xor(hex_word1, hex_word2)
    hex_word = []
    hex_word1.zip(hex_word2).each do |hex_byte1, hex_byte2|
      hex_xor = hex_byte_xor(hex_byte1, hex_byte2)
      hex_word << hex_xor
    end
    return hex_word
  end

  def hex_byte_xor(hex_byte1, hex_byte2)
    int_byte1 = hex_to_int(hex_byte1)
    int_byte2 = hex_to_int(hex_byte2)
    int_xor = int_byte1 ^ int_byte2
    hex_xor = int_to_hex(int_xor)
    return hex_xor
  end

  def string_to_hex_array(text)
    text.unpack('C*').map { |e| '%02x' % e }
  end

  # def string_to_unicodes(text)
  #   text.unpack('C*')
  # end
  #
  # def unicodes_to_hexs(unicodes)
  #   unicodes.map { |e| '%02x' % e }
  # end

  def hex_to_int(hex)
    hex.to_i 16
  end

  def int_to_hex(unicode)
    '%02x' % unicode
  end

  def hexs_to_unicodes(hexs)
    hexs.map { |e| e.to_i 16 }
  end

  # def unicodes_to_string(unicodes)
  #   unicodes.map(&:chr).join('')
  # end

  def hex_array_to_string(hex_array)
    hex_array.map { |e| e.to_i 16 }.map(&:chr).join('')
  end

  def hex_to_binary(hex)
    '%08b' % hex.to_i(16)
  end

  def binary_to_hex(binary)
    '%02x' % binary.to_i(2)
  end
end

# key = Aes.generate_random_key
# puts key
key = 'HEohOoOLrVwaECVv'
aes = Aes.new(key)
cipher_text = aes.encrypt('Hello, This is maruf here. I want to introduce myself with you!njjbuiyiy  !@##@#$##$$$')
puts "Cipher Text: #{cipher_text}"

plain_text = aes.decrypt(cipher_text)
puts "Plain Text: #{plain_text}"

# bytes = aes.string_to_bytes('Hello,Bangladesh')
# puts "Bytes: #{bytes.inspect}"
# hexs = aes.bytes_to_hexs(bytes)
# puts "Hex: #{hexs}"
# bytes = aes.hexs_to_bytes(hexs)
# puts "Bytes: #{bytes.inspect}"
# text = aes.bytes_to_string(bytes)
# puts "Text: #{text}"

# puts Aes::S_BOX_HEX[0][1]
# binary = aes.hex_to_binary(Aes::S_BOX_HEX[0][1])
# puts binary
# hex = aes.binary_to_hex(binary)
# puts hex
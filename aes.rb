require './constants.rb'

class Aes

  def initialize(key)
    key_length = key.length
    raise KeyError, "Key size #{key_length} is not supported" unless key_length == 16
    @key = key
    key_expansion
  end

  # --------------------------------------------------------------------------------------------------------------------
  # ------------------------------------------------- Encryption Methods -----------------------------------------------
  # --------------------------------------------------------------------------------------------------------------------

  def encrypt(plain_text)
    puts "\nEncryption: -----------------------------------------------------------------------------------------------"
    puts "Plain Text: #{plain_text}"
    blocks = break_into_blocks(plain_text)
    # puts blocks.inspect
    # convert_block_into_words(blocks.first)
    blocks = blocks.collect { |block| convert_block_into_words(block) }
    puts "Plain Text hex blocks: #{blocks.inspect}\n\n"

    output_cipher_blocks = []
    blocks.each_with_index do |block, index|
      # puts "Block #{index + 1}------------------"
      # puts "Input Block: #{block}"

      # First add round key before rounds
      key_words = @key_words[0..3]
      add_round_key_output = add_round_key(block, key_words)

      cipher_block = encrypt_rounds(add_round_key_output, 1)
      # puts "Cipher Block: #{cipher_block.inspect}"

      output_cipher_blocks << cipher_block
    end

    puts "Cipher blocks: #{output_cipher_blocks.inspect}"

    # Create hex stream from hex blocks
    cipher_text = combine_hex_blocks(output_cipher_blocks)

    return cipher_text
  end

  def encrypt_rounds(input_block, round)
    # Substitute Bytes step
    round_substitute_output = input_block.collect { |word| substitute_bytes(word) }
    # puts round_substitute_output.inspect

    # Shift rows step
    round_shift_rows_output = shift_rows(round_substitute_output)
    # puts round_shift_rows_output.inspect

    if round < 10
      # Mix Columns step
      round_mix_column_ouput = mix_columns(round_shift_rows_output)
      output_block = round_mix_column_ouput
    else
      output_block = round_shift_rows_output
    end

    # Add round key step
    key_words = @key_words[(round*4)..(round*4+3)]
    round_add_round_key_output = add_round_key(output_block, key_words)
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

  def combine_hex_blocks(blocks)
    hex_array = blocks.flatten
    hex_array = hex_array.map { |hex_byte| "0x#{hex_byte}" }
    return hex_array.join('')
  end

  # --------------------------------------------------------------------------------------------------------------------
  # ------------------------------------------------- Decryption Methods -----------------------------------------------
  # --------------------------------------------------------------------------------------------------------------------

  def decrypt(cipher_text)
    puts "\nDecryption: -----------------------------------------------------------------------------------------------"
    puts "Cipher Text: #{cipher_text}"
    blocks = break_cipher_texts_to_block(cipher_text)
    puts "Cipher Hex blocks: #{blocks.inspect}\n\n"

    output_plain_text_blocks = []

    blocks.each_with_index do |block, index|
      # puts "Block #{index + 1}------------------"
      # puts "Input Block: #{block}"

      # First add round key before rounds
      key_words = @key_words[40..43]
      add_round_key_output = add_round_key(block, key_words)

      plain_text_block = decrypt_rounds(add_round_key_output, 1)
      # puts "Plain Text Block: #{plain_text_block.inspect}"

      output_plain_text_blocks << plain_text_block
    end

    puts "Plain Text hex blocks: #{output_plain_text_blocks.inspect}"

    # Combine Plain Text blocks
    plain_text = combine_plain_text_blocks(output_plain_text_blocks)

    return plain_text
  end

  def break_cipher_texts_to_block(cipher_text)
    hex_array = cipher_text.split('0x').drop(1)
    blocks = hex_array.each_slice(16).to_a
    blocks = blocks.collect { |block| block.each_slice(4).to_a }
    # puts blocks.inspect
    return blocks
  end

  def decrypt_rounds(input_block, round)
    # Inverse Shift rows step
    round_shift_rows_output = shift_rows(input_block, reverse: true)
    # puts round_shift_rows_output.inspect

    # Inverse Substitute Bytes step
    round_substitute_output = round_shift_rows_output.collect { |word| substitute_bytes(word, reverse: true) }
    # puts round_substitute_output.inspect

    # Add round key step
    key_words = @key_words[((10-round)*4)..((10-round)*4+3)]
    round_add_round_key_output = add_round_key(round_substitute_output, key_words)
    # puts round_add_round_key_output.inspect

    if round < 10
      # Inverse Mix Columns step
      round_mix_column_ouput = mix_columns(round_add_round_key_output, reverse: true)
      output_block = round_mix_column_ouput
    else
      output_block = round_add_round_key_output
    end

    if round == 10
      return output_block
    else
      return decrypt_rounds(output_block, round + 1)
    end
  end

  def combine_plain_text_blocks(blocks)
    hex_array = blocks.flatten
    plain_text = hex_array_to_string(hex_array)
    plain_text.gsub!(/{*$/, '')
    return plain_text
  end

  # --------------------------------------------------------------------------------------------------------------------
  # ------------------------------------------------- Round Operations -----------------------------------------------
  # --------------------------------------------------------------------------------------------------------------------

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
  def substitute_bytes(hex_word, reverse: false)
    new_hex_word = []

    hex_word.each do |hex_byte|
      x, y = hex_byte.split('').map { |e| hex_to_int(e) }
      box_value = reverse ? INVERSE_S_BOX_HEX[x][y] : S_BOX_HEX[x][y]
      new_hex_word << box_value
    end

    return new_hex_word
  end

  def shift_rows(block, reverse: false)
    output_block = []
    block.each_with_index do |word, index|
      if index > 0
        shift_counter = reverse ? -index : index
        output_word = word.rotate(shift_counter)
      else
        output_word = word
      end
      output_block << output_word
    end

    return output_block
  end

  def mix_columns(block, reverse: false)
    matrix = reverse ? INVERSE_MIX_COLUMN_MATRIX : MIX_COLUMN_MATRIX
    output_block = matrix_multiplication(matrix, block)
    return output_block
  end

  def matrix_multiplication(a, b)
    output = []

    (0..3).each do |i|
      row = []
      (0..3).each do |k|
        temp = '00'
        (0..3).each do |m|
          temp = hex_byte_xor(temp, gf_multiplication(a[i][m], b[m][k]))
        end
        row << temp
      end
      output << row
    end

    return output
  end

  def gf_multiplication(a, b)
    if a == '01'
      return b
    elsif a == '02'
      output = gf2_multiply_by_02(b) # x2 -> 2
      return output
    elsif a == '03'
      output = gf2_multiply_by_02(b) # x2 -> 2
      output = hex_byte_xor(output, b) # +b -> 3
      return output
    elsif a == '09'
      output = gf2_multiply_by_02(b) # x2 -> 2
      output = gf2_multiply_by_02(output) # x2 -> 4
      output = gf2_multiply_by_02(output) # x2 -> 8
      output = hex_byte_xor(output, b) # +b -> 9
      return output
    elsif a == '0B' # 11
      output = gf2_multiply_by_02(b) # x2 -> 2
      output = gf2_multiply_by_02(output) # x2 -> 4
      output = hex_byte_xor(output, b) # +b -> 5
      output = gf2_multiply_by_02(output) # x2 -> 10
      output = hex_byte_xor(output, b) # +b -> 11
      return output
    elsif a == '0D' # 13
      output = gf2_multiply_by_02(b) # x2 -> 2
      output = hex_byte_xor(output, b) # +b -> 3
      output = gf2_multiply_by_02(output) # x2 -> 6
      output = gf2_multiply_by_02(output) # x2 -> 12
      output = hex_byte_xor(output, b) # +b -> 13
      return output
    elsif a == '0E' # 14
      output = gf2_multiply_by_02(b) # x2 -> 2
      output = hex_byte_xor(output, b) # +b -> 3
      output = gf2_multiply_by_02(output) # x2 -> 6
      output = hex_byte_xor(output, b) # +b -> 7
      output = gf2_multiply_by_02(output) # x2 -> 14
      return output
    end
  end

  def gf2_multiply_by_02(hex_byte)
    binary = hex_to_binary(hex_byte)
    left_most_bit = binary[0]
    binary[0] = ''
    binary += '0'
    output = binary_to_hex(binary)
    output = hex_byte_xor(output, '1B') if left_most_bit == '1'
    return output
  end

  # --------------------------------------------------------------------------------------------------------------------
  # ------------------------------------------------ Key Expansion Methods ---------------------------------------------
  # --------------------------------------------------------------------------------------------------------------------

  def key_expansion
    puts "Original Key: #{@key}"
    hex_array = string_to_hex_array(@key)
    puts "Key converted to Hex: #{hex_array.inspect}"

    @key_words = []
    hex_array.each_slice(4) { |a| @key_words << a }

    (4..43).each do |i|
      temp = @key_words[i-1]
      temp = hex_word_xor(substitute_bytes(rot_hex_word(temp)), r_con_hex_word(i/4)) if (i % 4 == 0)
      @key_words[i] = hex_word_xor(@key_words[i-4], temp)
    end

    puts "Expanded Key: #{@key_words.inspect}"
  end

  def rot_hex_word(hex_word)
    # one-byte circular left shift on a word
    return hex_word.rotate(1)
  end

  def r_con_hex_word(index)
    rc = R_CON_HEX[index-1]
    rcon = [rc, '00', '00', '00']
    return rcon
  end

  # --------------------------------------------------------------------------------------------------------------------
  # ---------------------------------------------------- Hex Operations  -----------------------------------------------
  # --------------------------------------------------------------------------------------------------------------------

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

  # --------------------------------------------------------------------------------------------------------------------
  # --------------------------------- Hex / Binary / Unicode / Character Conversions  ----------------------------------
  # --------------------------------------------------------------------------------------------------------------------

  def string_to_hex_array(text)
    text.unpack('C*').map { |e| '%02x' % e }
  end

  def hex_to_int(hex)
    hex.to_i 16
  end

  def int_to_hex(unicode)
    '%02x' % unicode
  end

  def hexs_to_unicodes(hexs)
    hexs.map { |e| e.to_i 16 }
  end

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
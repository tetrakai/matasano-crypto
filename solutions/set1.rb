require 'openssl'

class Set1
  # Utility functions
  def hex_to_bytes(arg); [arg].pack('H*'); end
  def bytes_to_hex(arg); arg.unpack('H*').first; end

  def bytes_to_base64(arg); [arg].pack('m0'); end
  def base64_to_bytes(arg); arg.unpack('m').first; end

  # Challenge 1
  def hex_to_base64(arg)
    bytes_to_base64(hex_to_bytes(arg))
  end

  # Challenge 2
  def xor_byte_strings(xor1, xor2)
    xored = xor1.chars.zip(xor2.chars).map do |c1, c2|
      (c1.ord ^ c2.ord).chr
    end

    xored.join('')
  end

  def xor_hex_strings(xor1, xor2)
    return bytes_to_hex(xor_byte_strings(hex_to_bytes(xor1), hex_to_bytes(xor2)))
  end

  # Challenge 3
  def get_string_score(str)
    return -1 if str.chars.any? {|c| c.ord >= 0x80 || c.ord < 0x0a}
    str.gsub(/[^a-zA-Z0-9 ]/, '').length.to_f / str.length.to_f
  end

  def find_single_byte_xor(str)
    results = (0x00..0xff).map do |c|
      decoded = xor_byte_strings(str, c.chr * str.length)
      [c, decoded, get_string_score(decoded)]
    end

    results.sort_by {|c, d, s| s}.reverse[0]
  end

  def find_single_byte_xor_hex(hexstr)
    find_single_byte_xor(hex_to_bytes(hexstr))
  end

  # Challenge 4
  def detect_single_byte_xor(filename)
    results = File.open(filename).each_line.map do |line|
      find_single_byte_xor_hex(line.strip)
    end

    results.sort_by{|c, d, s| s}.reverse[0]
  end

  # Challenge 5
  def encode_repeating_key_xor(msg, key)
    repeated_key = (key * ((msg.length / key.length) + 1))[0..msg.length - 1]
    xor_byte_strings(msg, repeated_key)
  end

  # Challenge 6
  def get_edit_distance(a, b)
    (a.chars.zip(b.chars).map {|c, d| (c.ord ^ d.ord).to_s(2).count('1')}).inject(:+)
  end

  def get_block(str, block_size, block_num)
    start_index = block_size * block_num
    end_index = (block_size * (block_num + 1)) - 1
    str[start_index..end_index]
  end

  def get_best_key_sizes(str, max_key_len=40, num_sample_blocks=10)
    results = (2..max_key_len).map do |key_len|
      # Get the edit distance between the first N block pairs
      distance = ((num_sample_blocks - 1).times.map do |i|
        get_edit_distance(get_block(str, key_len, i), get_block(str, key_len, i + 1))
      end).inject(:+)

      [key_len, (distance.to_f / key_len.to_f) / num_sample_blocks]
    end

    results.sort_by{|k, d| d}.map{|k, d| k}
  end

  def get_blocks(str, block_len)
    blocks = Hash.new('')
    str.chars.each_with_index {|c, i| blocks[i % block_len] += c}
    block_len.times.map {|i| blocks[i]}
  end

  def rpad_arr(arr, len, pad_with)
    arr.fill(pad_with, arr.length...len)
  end

  def flatten_blocks(blocks)
    (blocks.map {|b| rpad_arr(b.chars, blocks[0].length, '')}).transpose.join
  end

  def break_repeating_key_xor(contents)
    get_best_key_sizes(contents).each do |key_len|
      blocks = get_blocks(contents, key_len)

      results = blocks.map{|b| find_single_byte_xor(b)}
      # If any blocks decrypt invalidly, skip!
      next if results.any? {|_, _, score| score == -1}
      return flatten_blocks(results.map{|_, d, _| d})
    end
  end

  def break_repeating_key_xor_file(filename)
    break_repeating_key_xor(base64_to_bytes(File.open(filename).read))
  end

  # Challenge 7
  def decrypt_aes_ecb(to_decrypt, key)
    decipher = OpenSSL::Cipher.new('AES-128-ECB')
    decipher.decrypt
    decipher.key = key
    decipher.padding = 0
    decipher.update(to_decrypt) + decipher.final
  end

  def decrypt_aes_ecb_file(filename, key)
    c = base64_to_bytes(File.open(filename).read)
    decrypt_aes_ecb(c, key)
  end

  # Challenge 8
  def get_chunks(str, chunk_size)
    (0..str.length - 1).step(chunk_size).map do |i|
      str[i..(i + chunk_size - 1)]
    end
  end

  def detect_aes_ecb(ciphertexts)
    results = [ciphertexts[132]].map do |c|
      chunks = get_chunks(c, 16)

      # For each combination of chunks, check if they are identical
      num_identical_chunks = (chunks.each_with_index.map do |c1, i|
        (chunks.each_with_index.map do |c2, j|
          next if j <= i
          c1 == c2
        end).count(true)
      end).inject(:+)

      [c, num_identical_chunks]
    end

    results.sort_by{|l, s| s}.map{|l, _| l}.reverse[0]
  end

  def detect_aes_ecb_file(filename)
    bytes_to_hex(detect_aes_ecb(File.readlines(filename).map {|l| hex_to_bytes(l.strip)}))
  end

  # Tests
  def run_tests
    puts 'Running tests, takes a few seconds...'
    raise 'Challenge 1' unless hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d') == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    raise 'Challenge 2' unless xor_hex_strings('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965') == '746865206b696420646f6e277420706c6179'
    raise 'Challenge 3' unless find_single_byte_xor_hex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')[0] == 88
    raise 'Challenge 4' unless detect_single_byte_xor('../input/set1/chal4.txt')[1] == "Now that the party is jumping\n"
    raise 'Challenge 5' unless encode_repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", 'ICE') == hex_to_bytes('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')
    raise 'Challenge 6 - edit distance' unless get_edit_distance('this is a test', 'wokka wokka!!!') == 37
    raise 'Challenge 6 - break repeating key XOR' unless break_repeating_key_xor_file('../input/set1/chal6.txt').start_with?("I'm back and I'm ringin' the bell")
    raise 'Challenge 7' unless decrypt_aes_ecb_file('../input/set1/chal7.txt', 'YELLOW SUBMARINE').start_with?("I'm back and I'm ringin' the bell")
    raise 'Challenge 8' unless detect_aes_ecb_file('../input/set1/chal8.txt') == 'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a'
    puts 'All tests passed! You are AWESOME!'
  end
end

if __FILE__ == $0
  Set1.new.run_tests
end

require './aes.rb'
require './aes_key.rb'

key = AesKey.generate_random_key

# key = 'HEohOoOLrVwaECVv'
aes = Aes.new(key)

cipher_text = aes.encrypt('Hello, This is maruf here. I want to introduce myself with you!njjbuiyiy  !@##@#$##$$$')
puts "Cipher Text: #{cipher_text}"

plain_text = aes.decrypt(cipher_text)
puts "Plain Text: #{plain_text}"
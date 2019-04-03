class AesKey
  def self.generate_random_key(size: 16)
    set = [('a'..'z'), (0..9), ('A'..'Z')].map(&:to_a).flatten
    string = (0...size).map { set[rand(set.length)] }.join
    return string
  end
end
require 'AES'

class TestModule
  attr_reader :iv, :blocksize

  NAME = "TestModule(tm)"

  def initialize(data, key = nil, iv = nil, encrypted_data = nil)
    @blocksize = AES::BLOCKSIZE
    @key = key.nil? ? (1..16).map{rand(255).chr}.join : key
    @iv  = iv.nil?  ? (1..16).map{rand(255).chr}.join : iv
    @encrypted = encrypted_data.nil? ? AES.encrypt(data, @key, @iv) : encrypted_data

    puts()
    puts("-" * 80)
    puts("Generated test data:")
    puts("-" * 80)
    puts("key: #{@key.unpack("H*")}")
    puts("iv:  #{@iv.unpack("H*")}")
    puts("enc: #{@encrypted.unpack("H*")}")
    puts("-" * 80)
  end

  def get_encrypted_string()
    return @encrypted
  end

  def attempt_decrypt(iv, block)
      begin
        decrypted = AES.decrypt(block, @key, iv)
        return true
      rescue # TODO: Be more specific
        return false
      end
  end
end

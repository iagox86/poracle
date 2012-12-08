class Util
  def Util.strclean(str)
    newstr = ''

    str.each_char do |c|
      if(ord(c) < 0x20 || ord(c) > 0x7E)
        newstr += "."
      else
        newstr += c
      end
    end

    return newstr
  end

  def Util.ord(c)
    if(c.is_a?(Fixnum))
      return c
    end
    return c.unpack('C')[0]
  end
end

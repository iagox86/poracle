class Util
  def Util.strclean(str)
    newstr = ''

    str.each_char do |c|
      if(c.ord < 0x20 || c.ord > 0x7F)
        newstr += "."
      else
        newstr += c
      end
    end

    return newstr
  end
end

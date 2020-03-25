def s2u(s, m):
    length = len(s)
    align = length % 8
    s = s.ljust(length+align, '\x00')
    num = []
    num_str = ['0' for _ in range(8)]
    for i in range(length+align):
        if (i % 8 == 0 and i != 0):
            number = int('0x'+''.join(num_str), 16)
            if number != 0:
                num.append(number)
                num_str = ['0' for _ in range(8)]
        if m == 'l':
            num_str[7-i%8] = hex(ord(s[i]))[2:].rjust(2,'0')
        elif m == 'h':
            num_str[i%8] = hex(ord(s[i]))[2:].rjust(2,'0')
        else:
            raise Exception('[-] m can only be l or h!')
    number = int('0x'+''.join(num_str), 16)
    if number != 0:
        num.append(number)
        num_str = ['0' for _ in range(8)]
    return num

def s2u32(s, m):
    length = len(s)
    align = length % 4
    s = s.ljust(length+align, '\x00')
    num = []
    num_str = ['0' for _ in range(4)]
    for i in range(length+align):
        if (i % 4 == 0 and i != 0):
            number = int('0x'+''.join(num_str), 16)
            if number != 0:
                num.append(number)
                num_str = ['0' for _ in range(4)]
        if m == 'l':
            num_str[3-i%4] = hex(ord(s[i]))[2:].rjust(2,'0')
        elif m == 'h':
            num_str[i%4] = hex(ord(s[i]))[2:].rjust(2,'0')
        else:
            raise Exception('[-] m can only be l or h!')
    number = int('0x'+''.join(num_str), 16)
    if number != 0:
        num.append(number)
        num_str = ['0' for _ in range(4)]
    return num

# 16进制转2进制表
hex2bin_box = {'0': '0000', '1': '0001', '2': '0010', '3': '0011',
               '4': '0100', '5': '0101', '6': '0110', '7': '0111',
               '8': '1000', '9': '1001', 'a': '1010', 'b': '1011',
               'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111'}

# 16进制串转2进制串
hex2bin = lambda x: ''.join(hex2bin_box[i] for i in x)
# 2进制串转16进制串
bin2hex = lambda input: ''.join(hex(int(input[i:i+4], 2))[2:] for i in range(0, len(input), 4))
# 2进制串异或
def xor_bin(a, b):
    assert len(a) == len(b)
    return hex2bin(hex(int(a, 2) ^ int(b, 2))[2:]).rjust(len(a), '0')
# 16进制串异或
def xor_hex(a, b):
    assert len(a) == len(b)
    return hex(int(b, 16) ^ int(a, 16))[2:].rjust(len(a), '0')

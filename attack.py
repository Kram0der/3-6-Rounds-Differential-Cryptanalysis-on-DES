from DES import *

# 置换矩阵P的逆矩阵
inv_p = [9, 17, 23, 31, 13, 28, 2, 18,
         24, 16, 30, 6, 26, 20, 10, 1,
         8, 14, 25, 3, 4, 29, 11, 19,
         32, 12, 22, 7, 5, 27, 15, 21]
# 16进制转2进制表
hex2bin_box = {'0': '0000', '1': '0001', '2': '0010', '3': '0011',
               '4': '0100', '5': '0101', '6': '0110', '7': '0111',
               '8': '1000', '9': '1001', 'a': '1010', 'b': '1011',
               'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111'}

# 矩阵置换
matrix_trans = lambda str, box: ''.join(str[i - 1] for i in box)
# 16进制串转2进制串
hex2bin = lambda x: ''.join(hex2bin_box[i] for i in x)
# 二进制串异或
xor_bin = lambda a, b: hex2bin(hex(int(a, 2) ^ int(b, 2))[2:])
# 从整型输入获得S盒坐标
index_x = lambda x: (x >> 4 & 2) | (x & 1)
index_y = lambda x: (x >> 1) & 0xf
# 取第i个S盒的输出
S_box = lambda i, x: DES.s[i][index_x(x)][index_y(x)]

child_key = [{} for i in range(8)]
# S盒差分表
S_box_diff_table = [[[
            [] for _ in range(16)
        ] for _ in range(64)
    ] for x in range(8)]

# 计算S盒差分表
def get_S_box_diff_table():
    for i in range(8):
        for x in range(64):
            for in_xor in range(64):
                out_xor = S_box(i, x) ^ S_box(i, x ^ in_xor)
                S_box_diff_table[i][in_xor][out_xor].append(x)

# 一轮差分分析，传入两组明密文对
def DES_diff_round(P1, P2, C1, C2):
    P1 = hex2bin(P1.lower())
    P2 = hex2bin(P2.lower())
    C1 = hex2bin(C1.lower())
    C2 = hex2bin(C2.lower())

    L0, L0_ = P1[:32], P2[:32]
    R0, R0_ = P1[32:], P2[32:]
    Ln, Ln_ = C1[:32], C2[:32]
    Rn, Rn_ = C1[32:], C2[32:]

    in_xor = matrix_trans(xor_bin(Ln, Ln_), DES.expand_e)
    out_xor = matrix_trans(xor_bin(xor_bin(L0, L0_), xor_bin(Rn, Rn_)), inv_p)
    E = matrix_trans(Ln, DES.expand_e)

    for i in range(8):
        idx0 = i << 2
        idx1 = idx0 + (i << 1)
        for input in S_box_diff_table[i][int(in_xor[idx1:idx1 + 6], 2)][int(out_xor[idx0:idx0 + 4], 2)]:
            key = input ^ int(E[idx1:idx1 + 6], 2)
            if key in child_key[i]:
                child_key[i][key] += 1
            else:
                child_key[i][key] = 1

def get_key():
    round_key = ''


if __name__ == '__main__':
    get_S_box_diff_table()

    P_C = [('5E870BA0B559A8CF', '71BF939C0CEEE3B1'), ('E7C1F970B559A8CF', 'EAA6CE7BC9DB808B'),
           ('5D6F0803ED9FAC45', 'D99FDDD5A3016E53'), ('1EB2B007ED9FAC45', 'B49E2F61B4172078'),
           ('7ECF80BD2FE0EA99', 'C9BE22F6DA261B9A'), ('8B2CBE002FE0EA99', '2360C6F9ACD3982D'),
           ('97D2078984F010B4', '719849F28E5313BF'), ('4A5C783384F010B4', 'E4DDEEDB66776D42'),
           ('641E10E96186B8A0', '7918C1C6400F4AA2'), ('CA4E94596186B8A0', 'B8D0DC72CD2F6579')]

    for i in range(0, 10, 2):
        DES_diff_round(P_C[i][0], P_C[i + 1][0], P_C[i][1], P_C[i + 1][1])

    print(1)


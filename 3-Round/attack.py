from DES import *

#明密文对数
pairs = 3
# 置换矩阵P的逆矩阵
inv_p = [9, 17, 23, 31, 13, 28, 2, 18,
         24, 16, 30, 6, 26, 20, 10, 1,
         8, 14, 25, 3, 4, 29, 11, 19,
         32, 12, 22, 7, 5, 27, 15, 21]

possible_key = [{} for i in range(8)]
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
    L3, L3_ = C1[:32], C2[:32]
    R3, R3_ = C1[32:], C2[32:]

    in_xor = matrix_trans(xor_bin(L3, L3_), expand_e)
    out_xor = matrix_trans(xor_bin(xor_bin(L0, L0_), xor_bin(R3, R3_)), inv_p)
    E = matrix_trans(L3, expand_e)

    for i in range(8):
        idx0 = i << 2
        idx1 = idx0 + (i << 1)
        for input in S_box_diff_table[i][int(in_xor[idx1:idx1 + 6], 2)][int(out_xor[idx0:idx0 + 4], 2)]:
            key = input ^ int(E[idx1:idx1 + 6], 2)
            if key in possible_key[i]:
                possible_key[i][key] += 1
            else:
                possible_key[i][key] = 1

def get_key(P, C):
    child_key = ''
    # 选出达到阈值的key
    for i in range(8):
        for key in possible_key[i]:
            if possible_key[i][key] == pairs:
                child_key += ''.join(bin(key)[2:].rjust(6, '0'))
    # print(child_key)
    # 矩阵变换 循环右移
    key = ['*']*56
    for i in range(48):
        key[perm_matrix_after[i] - 1] = child_key[i]
    mov = move[2]
    key = key[28-mov:28] + key[:28-mov] + key[-mov:] + key[28:56-mov]

    # 需要填充的位置
    empty = []
    for i in range(56):
        if key[i] == '*':
            empty.append(i)

    temp_key = ''
    for i in range(1 << 8):
        rand = ''.join(bin(i)[2:].rjust(8, '0'))
        for j in range(8):
            key[empty[j]] = rand[j]
        temp_key = ''.join(key)
        # print(temp_key)
        if DES_3round_test(temp_key, P) == C.lower():
            key = ['*'] * 64
            for i in range(56):
                key[perm_matrix_before[i] - 1] = temp_key[i]
            key = ''.join(key)
            # 增加奇偶校验位
            key = ''.join(key[i:i + 7] + str(key[i:i + 7].count('0') & 1) for i in range(0, 64, 8))
            return bin2hex(key).upper()


if __name__ == '__main__':
    get_S_box_diff_table()

    P_C_pairs = [('748502CD38451097', '03C70306D8A09F10'), ('3874756438451097', '78560A0960E6D4CB'),
                 ('486911026ACDFF31', '45FA285BE5ADC730'), ('375BD31F6ACDFF31', '134F7915AC253457'),
                 ('357418DA013FEC86', 'D8A31B2F28BBC5CF'), ('12549847013FEC86', '0F317AC2B23CB944')]

    for i in range(0, pairs << 1, 2):
        DES_diff_round(P_C_pairs[i][0], P_C_pairs[i + 1][0], P_C_pairs[i][1], P_C_pairs[i + 1][1])
    print(get_key('748502CD38451097', '03C70306D8A09F10'))

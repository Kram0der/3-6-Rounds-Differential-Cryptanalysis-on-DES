import random
import time

from DES import *

# 轮数
N = 3
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


# 一轮差分分析，传入两对明密文对
def DES_diff_round(P1, P2, C1, C2):
    P1 = hex2bin(P1.lower())
    P2 = hex2bin(P2.lower())
    C1 = hex2bin(C1.lower())
    C2 = hex2bin(C2.lower())

    L0, L0_ = P1[:32], P2[:32]
    R0, R0_ = P1[32:], P2[32:]
    LN, LN_ = C1[:32], C2[:32]
    RN, RN_ = C1[32:], C2[32:]

    in_xor = matrix_trans(xor_bin(LN, LN_), expand_e)
    out_xor = matrix_trans(xor_bin(xor_bin(L0, L0_), xor_bin(RN, RN_)), inv_p)

    E = matrix_trans(LN, expand_e)
    for i in range(8):
        idx0 = i << 2
        idx1 = idx0 + (i << 1)
        for input in S_box_diff_table[i][int(in_xor[idx1:idx1 + 6], 2)][int(out_xor[idx0:idx0 + 4], 2)]:
            key = input ^ int(E[idx1:idx1 + 6], 2)
            if key in possible_key[i]:
                possible_key[i][key] += 1
            else:
                possible_key[i][key] = 1


def analyze(P, C):
    child_key = ''
    for i in range(8):
        # if (possible_key[i][0][1] == possible_key[i][1][1]):
        # return False
        child_key += bin(possible_key[i][0][0])[2:].rjust(6, '0')
    # return True
    # print(child_key)
    # 矩阵变换 循环右移
    key = ['*'] * 56
    for i in range(48):
        key[perm_matrix_after[i] - 1] = child_key[i]
    mov = move[2]
    key = key[28 - mov:28] + key[:28 - mov] + key[-mov:] + key[28:56 - mov]

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
        temp_key = bin2hex(''.join(key))
        # print(temp_key)
        if DES_Nround_test(temp_key, P, N) == C.lower():
            return temp_key.upper()


if __name__ == '__main__':
    # 计算S盒差分表
    get_S_box_diff_table()
    hex_table = "0123456789ABCDEF"
    pairs = 4

    P_C_pairs = [[[] for i in range(2)] for j in range(pairs << 1)]

    # 随机生成56位密钥
    key = ''.join(random.choice(hex_table) for i in range(14))
    # 随机生成64位明文和差分值
    for j in range(0, pairs << 1, 2):
        diff = ''.join(random.choice(hex_table) for i in range(8)) + '0' * 8
        P_C_pairs[j][0] = ''.join(random.choice(hex_table) for i in range(16))
        P_C_pairs[j + 1][0] = xor_hex(P_C_pairs[j][0], diff)
        P_C_pairs[j][1] = DES_Nround_test(key, P_C_pairs[j][0], N)
        P_C_pairs[j + 1][1] = DES_Nround_test(key, P_C_pairs[j + 1][0], N)

    for i in range(0, pairs << 1, 2):
        DES_diff_round(P_C_pairs[i][0], P_C_pairs[i + 1][0], P_C_pairs[i][1], P_C_pairs[i + 1][1])
    for i in range(8):
        possible_key[i] = sorted(possible_key[i].items(), key=lambda x: x[1], reverse=True)
    print("真实密钥:{0}\n攻击结果:{1}".format(key, analyze(P_C_pairs[0][0], P_C_pairs[0][1])))

    # 进行1000次测试
    # n = 1000
    # success = 0
    # start_time = time.time()
    # for _ in range(n):
    #     # 随机生成56位密钥
    #     key = ''.join(random.choice(hex_table) for i in range(14))
    #     # 随机生成64位明文和差分值
    #     for j in range(0, pairs << 1, 2):
    #         diff = ''.join(random.choice(hex_table) for i in range(8)) + '0'* 8
    #         P_C_pairs[j][0] = ''.join(random.choice(hex_table) for i in range(16))
    #         P_C_pairs[j + 1][0] = xor_hex(P_C_pairs[j][0], diff)
    #         P_C_pairs[j][1] = DES_Nround_test(key, P_C_pairs[j][0], N)
    #         P_C_pairs[j + 1][1] = DES_Nround_test(key, P_C_pairs[j + 1][0], N)
    #
    #     for i in range(0, pairs << 1, 2):
    #         DES_diff_round(P_C_pairs[i][0], P_C_pairs[i + 1][0], P_C_pairs[i][1], P_C_pairs[i + 1][1])
    #     for i in range(8):
    #         possible_key[i] = sorted(possible_key[i].items(), key=lambda x: x[1], reverse=True)
    #     success += analyze(P_C_pairs[0][0], P_C_pairs[0][1])
    #     possible_key = [{} for i in range(8)]
    # print("用时：{:.2f}s".format(time.time() - start_time))
    # print("成功率：{:.2f}%".format(success / n * 100))

    # with open("3rounds_analysis/possible_key.txt", "w") as f:
    #     for i in range(8):
    #         f.write(f"{i + 1}:\t")
    #         possible_key[i] = dict(sorted(possible_key[i].items(), key=lambda x:x[1], reverse=True))
    #         f.write(str(possible_key[i]))
    #         f.write("\n")

import random
import time
from DES import *

# 置换矩阵P的逆矩阵
inv_p = [9, 17, 23, 31, 13, 28, 2, 18,
         24, 16, 30, 6, 26, 20, 10, 1,
         8, 14, 25, 3, 4, 29, 11, 19,
         32, 12, 22, 7, 5, 27, 15, 21]

effective_position = [[1, 4, 5, 6, 7], [0, 1, 3, 4, 5]]
possible_key = [[{} for i in range(8)] for i in range(2)]
real_key = ''
# 合并两个密钥
def general(a, b):
    global real_key
    for i, j in zip(a, b):
        if i == '*':
            real_key += j
        elif j == '*':
            real_key += i
        else:
            if not i == j:
                return False
            real_key += i
    return True
# S盒差分表
S_box_diff_table = [[[
    [] for _ in range(16)
] for _ in range(64)
] for x in range(8)]
# 明密文对
PC_pairs = [[] for i in range(pairs)]


# 计算S盒差分表
def get_S_box_diff_table():
    for i in range(8):
        for x in range(64):
            for in_xor in range(64):
                out_xor = S_box(i, x) ^ S_box(i, x ^ in_xor)
                S_box_diff_table[i][in_xor][out_xor].append(x)


# 一轮差分分析，传入两组明密文对
def DES_diff_round(PC, k):
    P1 = hex2bin(PC[0].lower())
    P2 = hex2bin(PC[1].lower())
    C1 = hex2bin(PC[2].lower())
    C2 = hex2bin(PC[3].lower())

    L0, L0_ = P1[:32], P2[:32]
    R0, R0_ = P1[32:], P2[32:]
    L6, L6_ = C1[:32], C2[:32]
    R6, R6_ = C1[32:], C2[32:]

    in_xor = matrix_trans(xor_bin(L6, L6_), expand_e)
    out_xor = matrix_trans(xor_bin(xor_bin(R6, R6_), Feature_bin[k][32:]), inv_p)

    E = matrix_trans(L6, expand_e)

    for i in effective_position[k]:
        idx0 = i << 2
        idx1 = idx0 + (i << 1)
        for input in S_box_diff_table[i][int(in_xor[idx1:idx1 + 6], 2)][int(out_xor[idx0:idx0 + 4], 2)]:
            key = input ^ int(E[idx1:idx1 + 6], 2)
            if key in possible_key[k][i]:
                possible_key[k][i][key] += 1
            else:
                possible_key[k][i][key] = 1


def get_key():
    child_key = ['', '']
    global real_key
    for i in range(2):
        for j in range(8):
            if j not in effective_position[i]:
                child_key[i] += '*'*6
            else:
                child_key[i] += bin(possible_key[i][j][0][0])[2:].rjust(6, '0')
    # print(child_key)
    if not general(child_key[0], child_key[1]):
        return False

    key = ['*'] * 56
    for i in range(48):
        key[perm_matrix_after[i] - 1] = real_key[i]
    # print(key)
    mov = move[5]
    key = key[28 - mov:28] + key[:28 - mov] + key[-mov:] + key[28:56 - mov]

    # 需要填充的位置
    empty = []
    for i in range(56):
        if key[i] == '*':
            empty.append(i)
    l = len(empty)
    temp_key = ''
    for i in range(1 << l):
        rand = ''.join(bin(i)[2:].rjust(l, '0'))
        for j in range(l):
            key[empty[j]] = rand[j]
        temp_key = ''.join(key)
        # print(temp_key)
        if DES_6round_test(temp_key, PC_pairs[0][0]) == PC_pairs[0][2].lower():
            key = ['*'] * 64
            for i in range(56):
                key[perm_matrix_before[i] - 1] = temp_key[i]
            real_key = ''.join(key)
            # 增加奇偶校验位
            real_key = ''.join(real_key[i:i + 7] + str(real_key[i:i + 7].count('0') & 1) for i in range(0, 64, 8))
            real_key = bin2hex(real_key)
            return True


if __name__ == '__main__':
    start = time.time()
    get_S_box_diff_table()
    for _ in range(2):
        with open(f"Feature{_}.txt", "r") as f:
            for i in range(pairs):
                tmp = f.readline()
                PC_pairs[i] = [tmp[17 * j:17 * j + 16] for j in range(4)]
        for i in range(pairs):
            DES_diff_round(PC_pairs[i], _)

    for i in range(2):
        for j in range(8):
            possible_key[i][j] = sorted(possible_key[i][j].items(), key=lambda x:x[1], reverse=True)

    if get_key():
        print("攻击成功\n密钥为:\t",real_key)
        print("耗时为:\t", time.time() - start)
    else:
        print("攻击失败")

    # with open("possible_key.txt", "w") as f:
    #     for i in range(2):
    #         f.write(f"\n{i + 1}:\n")
    #         for j in range(8):
    #             possible_key[i][j] = dict(sorted(possible_key[i][j].items(), key=lambda x:x[1], reverse=True))
    #             f.write("\n")
    #             f.write(str(possible_key[i][j]))
    #         f.write("\n")

    # key = '1' * 12 + '*' * 6 + '1' * 30
    # ori_key = ['*'] * 56
    # for i in range(48):
    #     ori_key[perm_matrix_after[i] - 1] = key[i]
    # mov = move[5]
    # ori_key = ori_key[28 - mov:28] + ori_key[:28 - mov] + ori_key[-mov:] + ori_key[28:56 - mov]
    # print("key:\t", ''.join(ori_key))
    # round = 1
    # mov = move[round - 1]
    # tmp = ori_key[mov:28] + ori_key[:mov] + ori_key[28 + mov:] + ori_key[28:28 + mov]
    # print(f"第{round}轮密钥:\t" + ' '.join(matrix_trans(tmp, perm_matrix_after)[i:i + 6] for i in range(0, 48, 6)))
    # round = 3
    # mov = move[round - 1]
    # tmp = ori_key[mov:28] + ori_key[:mov] + ori_key[28 + mov:] + ori_key[28:28 + mov]
    # print(f"第{round}轮密钥:\t" + ' '.join(matrix_trans(tmp, perm_matrix_after)[i:i + 6] for i in range(0, 48, 6)))


from sm3 import *
def SM3_for_len_atk(pad,iv):
    #-----直接给定填充后分组的SM3-----
    # m = int(m, 16)
    # m_bitstr = Padding(m)
    # m_group = Group(m_bitstr)
    m_group = Group(pad)
    new_V = iv
    for B in m_group:
        W = Expand(B)
        new_V = CF(W, new_V)
    res = ''
    for x in new_V:
        res += '{:0>8x}'.format(x)
    return res
if __name__ == '__main__':
    raw='0x123456789123456789'#原始数据
    append='0x6666666666666666'#追加数据
    res_raw=SM3(raw,IV)#原始数据的hash值
    print(f'原始数据：{raw}')
    new_IV=[]#使用原始数据的hash值构造新的IV
    for i in range(8):
        new_IV.append(int(res_raw[i*8:i*8+8],16))#使用原始数据的hash值作为新的iv
    raw_pad=Padding(int(raw,16))#得到原始数据填充后的数据
    raw_pad_len=len(Group(raw_pad))*512#原始数据填充后长度
    append_len = len('{:b}'.format(int(append, 16)))#追加数据的长度
    if append_len % 4 != 0:
        append_len = len('0' * (4 - (append_len % 4)) + '{:b}'.format(int(append, 16)))
    #full_len='{:0>64b}'.format(append_len+raw_pad_len)
    append_pad=Padding(int(append,16))#追加数据填充后的数据
    real_append_pad='{:0>512b}'.format(int(append_pad,2)+raw_pad_len)#将追加数据填充后数据的64位数据长度修改为“原始数据+填充+追加数据”的总长度
    attack_res=SM3_for_len_atk(real_append_pad,new_IV)#使用原始数据的hash值作为新的iv，对填充且加工后的追加数据进行hash
    print(f'追加数据：{append}\n使用追加数据的攻击结果：{attack_res}')
    new_msg='{:x}'.format((int(raw_pad,2)<<append_len)+int(append,16))
    real_res=SM3(new_msg,IV)#将“原始数据+填充+追加数据”进行hash，用于结果正确性验证
    print(f'将‘原始数据+填充+追加数据‘进行hash的结果：{real_res}')
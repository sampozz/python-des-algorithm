'''
Implementazione algoritmo di codifica DES (Data Encryption Standard)
@author Pozzani Samuele
@date 28/12/2017
@version 1.0
'''

def hex_to_bin(stringa):
    '''La funzione ritorna il valore binario della stringa esadecimale'''
    dec_val = int(stringa, 16)
    bin_val = ''
    while dec_val != 0:
        bin_val = str(dec_val % 2) + bin_val
        dec_val = dec_val // 2
    return bin_val


def bin_to_hex(stringa):
    '''La funzione ritorna il valore esadecimale della stringa binaria'''
    dec_val = int(stringa, 2)
    hex_val = ''
    while dec_val != 0:
        if dec_val % 16 == 10:
            hex_val = 'A' + hex_val
        elif dec_val % 16 == 11:
            hex_val = 'B' + hex_val
        elif dec_val % 16 == 12:
            hex_val = 'C' + hex_val
        elif dec_val % 16 == 13:
            hex_val = 'D' + hex_val
        elif dec_val % 16 == 14:
            hex_val = 'E' + hex_val
        elif dec_val % 16 == 15:
            hex_val = 'F' + hex_val
        else:
            hex_val = str(dec_val % 16) + hex_val
        dec_val = dec_val // 16
    return hex_val


def rotate(lista, n):
    '''La funzione ruota verso sinistra la lista n volte'''
    return lista[n:] + lista[:n]


def f_xor(k, l_minus, r_minus):
    '''La funzione ritorna il valore del blocco r modificato secondo l'algoritmo DES'''

    # r_minus viene espanso da 32 a 48 bit attraverso la tabella e
    e = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]
    r_minus = ''.join([r_minus[i-1] for i in e])

    # viene fatto uno xor bit a bit tra k e r_minus
    xor_k_r = ''.join([str(int(k[i]) ^ int(r_minus[i])) for i in range(48)])

    # creazione s-boxes
    s_boxes = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
		[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
    ]

    # permutazione xor_k_r in s_boxes_out che diventa di 32 bit attraverso le s-boxes
    s_boxes_out = []
    j = 0
    for i in range(0, 48, 6):
        row = xor_k_r[i] + xor_k_r[i + 5]
        column = xor_k_r[(i + 1):(i + 5)]
        row = int(row, 2)
        column = int(column, 2)
        s_boxes_out.append(s_boxes[j][row][column])
        j += 1
    s_boxes_out = ["{0:b}".format(i) for i in s_boxes_out]
    for i in range(8):
        while len(s_boxes_out[i]) % 4 != 0:
            s_boxes_out[i] = '0' + s_boxes_out[i]
    s_boxes_out = ''.join(s_boxes_out)

    # s_boxes_out viene permutato attraverso la tabella p
    p = [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    ]
    s_boxes_out = ''.join([s_boxes_out[i-1] for i in p])

    # viene fatto uno xor bit a bit tra s_boxes_out e l_minus
    r_n = ''.join([str(int(s_boxes_out[i]) ^ int(l_minus[i])) for i in range(32)])
    return r_n


def encryption(m, k):
    '''La funzione ritorna il messaggio m codificato attraverso la chiave k secondo l'algoritmo DES'''

    while len(k) != 16:
        print('Errore. La chiave deve essere di 16 cifre esadecimali.')
        k = input('Inserisci la chiave di crittografia (16 cifre esadecimali): ')

    # conversione messaggio e chiave in binario
    m = hex_to_bin(m)
    while len(m) % 64 != 0:
        m = '0' + m
    k = hex_to_bin(k)
    while len(k) % 64 != 0:
        k = '0' + k

    # permutazione di k in k_plus attraverso la tabella pc_1
    pc_1 = [
            57, 49, 41, 33, 25, 17, 9, 1,
            58, 50, 42, 34, 26, 18, 10, 2,
            59, 51, 43, 35, 27, 19, 11, 3,
            60, 52, 44, 36, 63, 55, 47, 39,
            31, 23, 15, 7, 62, 54, 46, 38,
            30, 22, 14, 6, 61, 53, 45, 37,
            29, 21, 13, 5, 28, 20, 12, 4
        ]
    k_plus = ''.join([k[i-1] for i in pc_1])

    # creazione di 16 subkeys
    c_0 = k_plus[:28]
    d_0 = k_plus[28:]
    left_shifts = [0, 1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28]
    c_subkeys_dict = {
        'c_' + str(i): rotate(c_0, left_shifts[i]) for i in range(1, 17)
    }
    d_subkeys_dict = {
        'd_' + str(i): rotate(d_0, left_shifts[i]) for i in range(1, 17)
    }

    # unione c_n e d_n e permutazione attraverso la tabella pc_2
    k_subkeys_dict = {
        'k_' + str(i): c_subkeys_dict['c_' + str(i)] + d_subkeys_dict['d_' + str(i)] for i in range(1, 17)
    }
    pc_2 = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]
    k_subkeys_dict = {
        'k_' + str(i): ''.join([k_subkeys_dict['k_' + str(i)][j - 1] for j in pc_2]) for i in range(1, 17)
    }

    # m viene permutato in m_plus attraverso la tabella ip e diviso in l_0 e r_0
    ip = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]
    m_plus = ''.join([m[i-1] for i in ip])
    l_minus = m_plus[:32]
    r_minus = m_plus[32:]

    # viene utilizzata la funzione f_xor per ottenere i due blocchi finali
    for i in range(1, 17):
        l_n = r_minus
        r_minus = f_xor(k_subkeys_dict['k_' + str(i)], l_minus, r_minus)
        l_minus = l_n
    final_block = r_minus + l_minus

    # il blocco finale viene permutato attraverso la tabella ip_1
    ip_1 = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25,
    ]
    final_block = ''.join([final_block[i-1] for i in ip_1])

    # conversione messaggio cifrato da binario a esadecimale
    final_block = bin_to_hex(final_block)
    return final_block


if __name__ == '__main__':

    # input
    m = input('Inserisci il messaggio da codificare (valori esadecimali): ')
    k = input('Inserisci la chiave di crittografia (16 cifre esadecimali): ')

    # divisione di m in blocchi da 64 bit e codifica
    n_blocks = len(m) // 16
    if len(m) % 16 != 0:
        n_blocks += 1
    c = ''
    for i in range(n_blocks):
        c = c + encryption(m[(i * 16):((i + 1) * 16)], k)

    print('Messaggio codificato:', c)
    input('Premi invio per uscire...')

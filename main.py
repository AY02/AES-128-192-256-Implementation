# https://en.wikipedia.org/wiki/Advanced_Encryption_Standard (Main source we relied on for the implementation)
# https://legacy.cryptool.org/en/cto/aes-step-by-step (Used to check the correctness of the functions for AES128)

#import secrets # Required for token_bytes()
import sys # Required for handle errors and exceptions
from enum import Enum # Required for choice options

# Names of input and output files to hold the keys and text and to print the ciphertext
KEY_FILENAME = 'key.txt'
INPUT_FILENAME = 'plaintext.txt'
OUTPUT_FILENAME = 'ciphertext.txt'
IV_FILENAME = 'initialization_vector.txt'

# Constants used to identify the return values ​​of sys.exit() on error
ERROR_FILE_OPENING_EXIT_CODE = 1
ERROR_FORMAT_EXIT_CODE = 2
ERROR_INPUT_EXIT_CODE = 3

BLOCK_SIZE = 16 # Size in bytes of each plaintext block

class N_ROUNDS_OPTIONS(Enum):
    """
    Number of rounds + initial round for AES (AES128 -> 10 + 1, AES192 -> 12 + 1, AES256 -> 14 + 1).
    """
    AES128 = 10 + 1
    AES192 = 12 + 1
    AES256 = 14 + 1
N_ROUNDS = None # It is decided at the input stage

class KEY_SIZE_OPTIONS(Enum):
    """
    Size in bytes of the key in AES (AES128 -> 16, AES192 -> 24, AES256 -> 32).
    """
    AES128 = 16
    AES192 = 24
    AES256 = 32
KEY_SIZE = None # It is decided at the input stage

ROUND_KEY_SIZE = 16 # Size in bytes of each round key

class MODE_OPTIONS(Enum):
    """
    Possible options for mode of operation.
    """
    ECB = 0
    CBC = 1
MODE = None # It is decided at the input stage

S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
) # AES S-box (https://en.wikipedia.org/wiki/Rijndael_S-box)

def sum_aes(a, b):
    """
    Implementation of the sum over GF(2^8).
    """
    return a ^ b

def product_aes(a, b):
    """
    Implementation of the product over GF(2^8).
    """
    polynomial = 0x11b
    result = 0x00
    for i in range(8):
        if b & 1:
            result ^= a
        b >>= 1
        if a & 0x80:
            a <<= 1
            a ^= polynomial
        else:
            a <<= 1
    return result

def sub_byte(byte):
    """
    Non-linear substitution of a byte by using the AES S-box.
    """
    return S_BOX[byte]

def rot_word(word):
    """
    1-byte left circular shift.
    """
    word = tuple(word)
    return bytes((word[1], word[2], word[3], word[0]))

def sub_word(word):
    """
    Application of the AES S-box to each byte of the word.
    """
    word = tuple(word)
    return bytes((sub_byte(word[0]), sub_byte(word[1]), sub_byte(word[2]), sub_byte(word[3])))

def key_expansion(key):
    """
    Key expansion step (https://en.wikipedia.org/wiki/AES_key_schedule).
    """
    R_CON = (
        (0x01, 0x00, 0x00, 0x00),
        (0x02, 0x00, 0x00, 0x00),
        (0x04, 0x00, 0x00, 0x00),
        (0x08, 0x00, 0x00, 0x00),
        (0x10, 0x00, 0x00, 0x00),
        (0x20, 0x00, 0x00, 0x00),
        (0x40, 0x00, 0x00, 0x00),
        (0x80, 0x00, 0x00, 0x00),
        (0x1B, 0x00, 0x00, 0x00),
        (0x36, 0x00, 0x00, 0x00)
    ) # Round costants
    N = KEY_SIZE // 4 # Length of the key in 32-bit words
    K = [] # Split the key in N 32-bit words
    for i in range(N):
        K.append(key[i * 4:i * 4 + 4])
    R = N_ROUNDS # Number of round keys needed
    W = [] # 32-bit words of the expanded key
    for i in range(4 * R):
        if i < N:
            W.append(K[i])
        elif (i >= N) and (i % N == 0):
            tmp1 = W[i - N]
            tmp2 = sub_word((rot_word(W[i - 1])))
            tmp3 = R_CON[(i // N) - 1]
            tmp = (a ^ b ^ c for a, b, c in zip(tmp1, tmp2, tmp3))
            W.append(bytes(tmp))
        elif (i >= N) and (N > 6) and (i % N == 4):
            tmp1 = W[i - N]
            tmp2 = sub_word(W[i - 1])
            tmp = (a ^ b for a, b in zip(tmp1, tmp2))
            W.append(bytes(tmp))
        else:
            tmp1 = W[i - N]
            tmp2 = W[i - 1]
            tmp = (a ^ b for a, b in zip(tmp1, tmp2))
            W.append(bytes(tmp))
    round_keys = tuple(b''.join(W[i:i + 4]) for i in range(0, 4 * R, 4))
    return round_keys

def pkcs_padding(plaintext):
    """
    PKCS#7 padding method is used (https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method).
    """
    padding_length = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
    padding = bytes((padding_length,)) * padding_length
    return plaintext + padding

def display_state(state):
    """
    Displays a state in matrix format.
    """
    for row in state:
        for byte in row:
            print(f'0x{byte:02x}', end=' ')
        print('\n')

def block_to_state(block):
    """
    Conversion of a plaintext block (or a round key) to a 4 x 4 matrix (state).
    """
    return [
        [block[0], block[4], block[8], block[12]],
        [block[1], block[5], block[9], block[13]],
        [block[2], block[6], block[10], block[14]],
        [block[3], block[7], block[11], block[15]]
    ]

def plaintext_to_blocks(plaintext):
    """
    Converts an utf-8 string to a 128-bit blocks.
    """
    return tuple(plaintext[i:i + BLOCK_SIZE] for i in range(0, len(plaintext), BLOCK_SIZE))

def plaintext_to_states(plaintext):
    """
    Converts an utf-8 string to a tuple of 128-bit states (it is used only on ECB mode).
    """
    plaintext = plaintext.encode('utf-8')
    plaintext = pkcs_padding(plaintext)
    blocks = plaintext_to_blocks(plaintext)
    states = [block_to_state(blocks[i]) for i in range(len(blocks))]
    return states

def states_to_text(states):
    """
    Converts a set of byte states into a single concatenated sequence of bytes in hexadecimal.
    """
    text = bytearray()
    for i in range(len(states)):
        for j in range(4):
            for z in range(4):
                text.append(states[i][z][j])
    return text.hex()

def xor_states(state1, state2):
    """
    Xor byte-to-byte between two states.
    """
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            new_state[i][j] = state1[i][j] ^ state2[i][j]
    return new_state

def xor_cbc(previous_encryption, state):
    """
    Each byte of the state is combined with a byte of the previously computed encrypted state using bitwise xor.
    """
    return xor_states(previous_encryption, state)

def add_round_key(key, state):
    """
    Each byte of the state is combined with a byte of the round key using bitwise xor.
    """
    key_state = block_to_state(key)
    return xor_states(key_state, state)

def initial_round_key_addition(key0, state):
    """
    Initial round key addition step.
    """
    new_state = add_round_key(key0, state)
    return new_state

def sub_bytes(state):
    """
    S-Box application on the state.
    """
    return [
        [sub_byte(state[0][0]), sub_byte(state[0][1]), sub_byte(state[0][2]), sub_byte(state[0][3])],
        [sub_byte(state[1][0]), sub_byte(state[1][1]), sub_byte(state[1][2]), sub_byte(state[1][3])], 
        [sub_byte(state[2][0]), sub_byte(state[2][1]), sub_byte(state[2][2]), sub_byte(state[2][3])], 
        [sub_byte(state[3][0]), sub_byte(state[3][1]), sub_byte(state[3][2]), sub_byte(state[3][3])]
    ]

def shift_rows(state):
    """
    Transposition step where the last three rows of the state are shifted cyclically a certain number of steps.
    """
    return [
        [state[0][0], state[0][1], state[0][2], state[0][3]],
        [state[1][1], state[1][2], state[1][3], state[1][0]],
        [state[2][2], state[2][3], state[2][0], state[2][1]],
        [state[3][3], state[3][0], state[3][1], state[3][2]]
    ]

def mix_columns(state):
    """
    Linear mixing operation which operates on the columns of the state, combining the four bytes in each column.
    """
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    MIX_COLUMNS_MATRIX = (
        (0x02, 0x03, 0x01, 0x01),
        (0x01, 0x02, 0x03, 0x01),
        (0x01, 0x01, 0x02, 0x03),
        (0x03, 0x01, 0x01, 0x02)
    ) # Fixed mix column matrix (https://en.wikipedia.org/wiki/Rijndael_MixColumns)
    for i in range(4):
        column = [state[0][i], state[1][i], state[2][i], state[3][i]]
        # Product between matrices 4 x 4 and 4 x 1
        for j in range(4):
            p0 = product_aes(MIX_COLUMNS_MATRIX[j][0], column[0])
            p1 = product_aes(MIX_COLUMNS_MATRIX[j][1], column[1])
            p2 = product_aes(MIX_COLUMNS_MATRIX[j][2], column[2])
            p3 = product_aes(MIX_COLUMNS_MATRIX[j][3], column[3])
            new_state[j][i] = sum_aes(sum_aes(p0, p1), sum_aes(p2, p3))
    return new_state

def encrypt_state(round_keys, state):
    """
    Single block encryption function.
    """
    new_state = initial_round_key_addition(round_keys[0], state) # Round 0
    # Round from 1 to (Last - 1)
    for i in range(1, N_ROUNDS - 1):
        new_state = sub_bytes(new_state)
        new_state = shift_rows(new_state)
        new_state = mix_columns(new_state)
        new_state = add_round_key(round_keys[i], new_state)
    # Last round
    new_state = sub_bytes(new_state)
    new_state = shift_rows(new_state)
    new_state = add_round_key(round_keys[N_ROUNDS - 1], new_state)
    return new_state

def aes_encrypt(key, plaintext, iv = None):
    """
    Main encryption function.
    """

    encrypt_states = []
    round_keys = key_expansion(key)

    if MODE == MODE_OPTIONS.ECB.value:

        states = plaintext_to_states(plaintext)
        encrypt_states = [encrypt_state(round_keys, states[i]) for i in range(len(states))]
        
    elif MODE == MODE_OPTIONS.CBC.value:

        plaintext = plaintext.encode('utf-8')
        plaintext = pkcs_padding(plaintext)
        blocks = plaintext_to_blocks(plaintext)

        first_state = xor_cbc(block_to_state(iv), block_to_state(blocks[0]))
        encrypt_states.append(encrypt_state(round_keys, first_state))

        for i in range(1, len(blocks)):
            current_state = block_to_state(blocks[i])
            previous_state = encrypt_states[i - 1]
            current_state = xor_cbc(previous_state, current_state)
            encrypt_states.append(encrypt_state(round_keys, current_state))

    return states_to_text(encrypt_states)

class AES_OPTIONS(Enum):
    """
    Possible options for AES.
    """
    AES128 = 0
    AES192 = 1
    AES256 = 2

def get_aes_name_from_option(value):
    """
    Function to get the AES option name associated with a value.
    """
    for option in AES_OPTIONS:
        if option.value == value:
            return option.name
    return None

def get_mode_name_from_option(value):
    """
    Function to get the mode option name associated with a value.
    """
    for option in MODE_OPTIONS:
        if option.value == value:
            return option.name
    return None

def get_key_from_file():
    """
    Reads the file containing the key and returns the string representing it.
    """
    try:
        with open(KEY_FILENAME, 'r') as file:
            key = file.read()
        return key
    except Exception as e:
        print(f'Error opening key file: {e}.')
        sys.exit(ERROR_FILE_OPENING_EXIT_CODE)

def key_correctness_check(key):
    """
    Check if the key is in a correct format.
    """
    if len(key) != KEY_SIZE:
        print(f'The key is not {8 * KEY_SIZE} bit, try again with a {KEY_SIZE}-byte string.')
        sys.exit(ERROR_FORMAT_EXIT_CODE)

def get_plaintext_form_file():
    """
    Reads the file containing the plaintext and returns the string representing it.
    """
    try:
        with open(INPUT_FILENAME, 'r') as file:
            plaintext = file.read()
        return plaintext
    except Exception as e:
        print(f'Error opening plaintext file: {e}.')
        sys.exit(ERROR_FILE_OPENING_EXIT_CODE)

def get_iv_from_file():
    """
    Reads the file containing the initialization vector and returns the string representing it.
    """
    try:
        with open(IV_FILENAME, 'r') as file:
            iv = file.read()
        return iv
    except Exception as e:
        print(f'Error opening iv file: {e}.')
        sys.exit(ERROR_FILE_OPENING_EXIT_CODE)

def iv_correctness_check(iv):
    """
    Check if the iv is in a correct format.
    """
    if len(iv) != BLOCK_SIZE:
        print(f'The iv is not 128 bit, try again with a 32-byte string.')
        sys.exit(ERROR_FORMAT_EXIT_CODE)

if __name__ == '__main__':

    aes_option_string = [f'{option.value}: {option.name}' for option in AES_OPTIONS]
    try:
        aes_choice = int(input(f'Choose which AES to use {aes_option_string} -> '))
    except Exception as e:
        print(f'Error while inputting choice: {e}')
        sys.exit(ERROR_INPUT_EXIT_CODE)
    if aes_choice not in [option.value for option in AES_OPTIONS]:
        print('Invalid choice.')
        sys.exit(ERROR_INPUT_EXIT_CODE)
    print(f'You have chosen the option {get_aes_name_from_option(aes_choice)}.')
    N_ROUNDS = N_ROUNDS_OPTIONS[get_aes_name_from_option(aes_choice)].value
    KEY_SIZE = KEY_SIZE_OPTIONS[get_aes_name_from_option(aes_choice)].value
    print(f'Number of rounds: {N_ROUNDS - 1} + 1')
    print(f'Size of the key: {KEY_SIZE}\n')

    mode_option_string = [f'{option.value}: {option.name}' for option in MODE_OPTIONS]
    try:
        mode_choice = int(input(f'Choose which mode of operation to use {mode_option_string} -> '))
    except Exception as e:
        print(f'Error while inputting choice: {e}')
        sys.exit(ERROR_INPUT_EXIT_CODE)
    if mode_choice not in [option.value for option in MODE_OPTIONS]:
        print('Invalid choice.')
        sys.exit(ERROR_INPUT_EXIT_CODE)
    print(f'You have chosen the option {get_mode_name_from_option(mode_choice)}.\n')
    MODE = mode_choice

    print(f'Retrieving the key from the file {KEY_FILENAME}...')
    #key = secrets.token_bytes(16) # Generate a random 16 byte key
    key = get_key_from_file()
    print(f'Key obtained:\n{key}')
    print(f'Checking the key correctness...')
    key_correctness_check(key)
    print(f'The key is in a correct format.\n')
    key = bytes.fromhex(key.encode('utf-8').hex())

    print(f'Retrieving the plaintext from the file {INPUT_FILENAME}...')
    plaintext = get_plaintext_form_file()
    print(f'Plaintext obtained:\n{plaintext}\n')

    if MODE == MODE_OPTIONS.CBC.value:
        print(f'Retrieving the initialization vector from the file {IV_FILENAME}...')
        iv = get_iv_from_file()
        print(f'Initialization vector obtained:\n{iv}')
        print(f'Checking the iv correctness...')
        iv_correctness_check(iv)
        print(f'The iv is in a correct format.\n')
        iv = bytes.fromhex(iv.encode('utf-8').hex())

    print('Start encryption...')
    if MODE == MODE_OPTIONS.ECB.value:
        ciphertext = aes_encrypt(key, plaintext)
    elif MODE == MODE_OPTIONS.CBC.value:
        ciphertext = aes_encrypt(key, plaintext, iv)
    print(f'Ciphertext: \n{ciphertext}')
import secrets
import json

# Funções de criptografia (mesmas do seu código anterior)
def generate_random_swap_key(length):
    swap_key = list(range(length))  # Índices de 0 a length-1
    secrets.SystemRandom().shuffle(swap_key)  # Embaralha os índices
    return bytearray(swap_key)

def generate_random_xor_key(length):
    xor_key = secrets.token_bytes(length)
    return xor_key

def circular_left_shift(byte, shift_amount):
    return ((byte << shift_amount) & 0xFF) | (byte >> (8 - shift_amount))

def xor_shift_encrypt(data, key):
    encrypted_data = bytearray()
    for i in range(len(data)):
        key_byte = key[i % len(key)]
        xor_byte = data[i] ^ key_byte
        shifted_byte = circular_left_shift(xor_byte, 1)
        final_byte = shifted_byte ^ key_byte
        encrypted_data.append(final_byte)
    return encrypted_data

def swap_positions(data_block, key):
    swapped_block = bytearray(data_block)
    for i in range(0, len(key), 2):
        if i + 1 < len(key):
            pos1 = key[i] % len(data_block)
            pos2 = key[i + 1] % len(data_block)
            swapped_block[pos1], swapped_block[pos2] = swapped_block[pos2], swapped_block[pos1]
    return swapped_block

def swap_cipher_encrypt(data, key):
    encrypted_data = bytearray()
    key = bytearray(key)
    for i in range(0, len(data), len(key)):
        block = data[i:i + len(key)]
        encrypted_block = swap_positions(block, key)
        encrypted_data.extend(encrypted_block)
    return encrypted_data

def combined_encrypt(data, swap_key, xor_key):
    swapped_data = swap_cipher_encrypt(data, swap_key)
    encrypted_data = xor_shift_encrypt(swapped_data, xor_key)
    return encrypted_data

def generate_keys(n, swap_key_length, xor_key_length):
    swap_keys = [generate_random_swap_key(swap_key_length) for _ in range(n)]
    xor_keys = [generate_random_xor_key(xor_key_length) for _ in range(n)]
    return swap_keys, xor_keys

def encrypt_with_multiple_keys(data, swap_keys, xor_keys):
    encrypted_data = data
    for i in range(len(swap_keys)):
        swap_key = swap_keys[i]
        xor_key = xor_keys[i]
        encrypted_data = combined_encrypt(encrypted_data, swap_key, xor_key)
    return encrypted_data

def test_collisions(num_tests, swap_key_length, xor_key_length, data_length):
    seen_encrypted_data = set()  # Conjunto para armazenar os dados criptografados
    collisions = 0

    for _ in range(num_tests):
        # Gera um dado aleatório de comprimento `data_length`
        data = secrets.token_bytes(data_length)

        # Gera as chaves de criptografia
        swap_key = generate_random_swap_key(swap_key_length)
        xor_key = generate_random_xor_key(xor_key_length)

        # Criptografa os dados
        encrypted_data = combined_encrypt(data, swap_key, xor_key)

        # Converte o bytearray para bytes
        encrypted_data_bytes = bytes(encrypted_data)

        # Verifica se o resultado já foi visto (colisão)
        if encrypted_data_bytes in seen_encrypted_data:
            collisions += 1
        else:
            seen_encrypted_data.add(encrypted_data_bytes)

    return collisions
# Parâmetros do teste
num_tests = 10000000  # Número de testes a serem realizados
swap_key_length = 8  # Tamanho da chave de troca
xor_key_length = 16  # Tamanho da chave XOR
data_length = 16  # Tamanho dos dados a serem criptografados

# Executar o teste de colisões
num_collisions = test_collisions(num_tests, swap_key_length, xor_key_length, data_length)

# Exibir o resultado do teste
print(f"Número de colisões encontradas em {num_tests} testes: {num_collisions}")

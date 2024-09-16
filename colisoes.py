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

# Função para teste de colisões e salvar os resultados em um JSON
def collision_test(data, n_values, num_trials, block_size, output_file):
    results = {}  # Armazena resultados de criptografias únicas
    collisions = 0  # Contador de colisões
    collision_data = []  # Lista para armazenar informações do teste
    colidiu = False

    for n in n_values:
        for _ in range(num_trials):
            swap_keys, xor_keys = generate_keys(n, block_size, block_size)
            encrypted_data = encrypt_with_multiple_keys(data, swap_keys, xor_keys)
            encrypted_data_hex = encrypted_data.hex()  # Representação hexadecimal para comparação
            
            if encrypted_data_hex in results:
                collisions += 1  # Incrementa o contador de colisões
                colidiu = True
            else:
                results[encrypted_data_hex] = (n, swap_keys, xor_keys)
            
            # Salvar os dados de cada tentativa em uma lista
            collision_data.append({
                "n": n,
                "trial": _ + 1,
                "encrypted_data": encrypted_data_hex,
                "collision": colidiu
            })
            colidiu = False
    
    # # Salva os dados em um arquivo JSON
    # with open(output_file, 'w') as f:
    #     json.dump(collision_data, f, indent=4)
    
    print(f"Número de colisões: {collisions} em {num_trials * len(n_values)} tentativas.")
    print(f"Os dados foram salvos no arquivo {output_file}.")

# Parâmetros do teste
n_values = range(1, 21)  # Testar valores de n de 1 até 20
# num_trials = 10  # Número de tentativas para cada valor de n
num_trials = 100000  # Número de tentativas para cada valor de n
data = b'Hello, World!'  # Dados de exemplo
block_size = len(data)  # Tamanho do bloco

# Nome do arquivo JSON para salvar os resultados
output_file = "collision_test_results.json"

# Execução do teste de colisões e salvamento em JSON
collision_test(data, n_values, num_trials, block_size, output_file)

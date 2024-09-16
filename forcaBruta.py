import time
import json
import itertools
import secrets
from random import sample
import gc

def generate_random_swap_key(length):
    # Gera uma chave aleatória de índices de tamanho `length`, embaralhando os índices
    swap_key = list(range(length))  # Índices de 0 a length-1
    secrets.SystemRandom().shuffle(swap_key)  # Embaralha os índices
    return bytearray(swap_key)

def generate_random_xor_key(length):
    # Gera uma sequência aleatória de bytes para a xor_key
    xor_key = secrets.token_bytes(length)
    return xor_key

def circular_left_shift(byte, shift_amount):
    return ((byte << shift_amount) & 0xFF) | (byte >> (8 - shift_amount))

def circular_right_shift(byte, shift_amount):
    return (byte >> shift_amount) | ((byte << (8 - shift_amount)) & 0xFF)

def xor_shift_encrypt(data, key):
    encrypted_data = bytearray()
    for i in range(len(data)):
        key_byte = key[i % len(key)]
        xor_byte = data[i] ^ key_byte
        shifted_byte = circular_left_shift(xor_byte, 1)
        final_byte = shifted_byte ^ key_byte
        encrypted_data.append(final_byte)
    return encrypted_data

def xor_shift_decrypt(encrypted_data, key):
    decrypted_data = bytearray()
    for i in range(len(encrypted_data)):
        key_byte = key[i % len(key)]
        xor_byte = encrypted_data[i] ^ key_byte
        shifted_byte = circular_right_shift(xor_byte, 1)
        final_byte = shifted_byte ^ key_byte
        decrypted_data.append(final_byte)
    return decrypted_data

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

def swap_cipher_decrypt(encrypted_data, key):
    decrypted_data = bytearray()
    key = bytearray(key)
    for i in range(0, len(encrypted_data), len(key)):
        block = encrypted_data[i:i + len(key)]
        decrypted_block = swap_positions(block, key)
        decrypted_data.extend(decrypted_block)
    return decrypted_data

def combined_encrypt(data, swap_key, xor_key):
    # Aplicando SwapCipher
    swapped_data = swap_cipher_encrypt(data, swap_key)
    # Aplicando XORShift
    encrypted_data = xor_shift_encrypt(swapped_data, xor_key)
    return encrypted_data

def combined_decrypt(encrypted_data, swap_key, xor_key):
    # Descriptografando XORShift
    decrypted_xor = xor_shift_decrypt(encrypted_data, xor_key)
    # Descriptografando SwapCipher
    decrypted_data = swap_cipher_decrypt(decrypted_xor, swap_key)
    return decrypted_data

# Função para gerar n swap_keys e n xor_keys
def generate_keys(n, swap_key_length, xor_key_length):
    swap_keys = [generate_random_swap_key(swap_key_length) for _ in range(n)]  # Lista de n swap_keys
    xor_keys = [generate_random_xor_key(xor_key_length) for _ in range(n)]     # Lista de n xor_keys
    return swap_keys, xor_keys


# Função para criptografar com n pares de chaves e concatenar os resultados
def encrypt_with_multiple_keys(data, swap_keys, xor_keys):
    encrypted_data = data  # Começa com os dados originais
    concatenated_result = bytearray()  # Armazena o resultado final concatenado
    
    for i in range(len(swap_keys)):
        swap_key = swap_keys[i]
        xor_key = xor_keys[i]
        # Criptografa o dado com a chave atual
        encrypted_data = combined_encrypt(encrypted_data, swap_key, xor_key)
        # Concatena o resultado criptografado
        concatenated_result.extend(encrypted_data)
    
    return concatenated_result

# Função para separar n textos encriptados concatenados e descriptografar o primeiro
def separate_and_decrypt_first(final_encrypted, swap_keys, xor_keys, block_size):
    encrypted_blocks = []
    
    # Calcula o tamanho de cada bloco encriptado
    current_position = 0
    for i in range(len(swap_keys)):
        # O tamanho de cada bloco é dado pelo tamanho original do bloco
        encrypted_block = final_encrypted[current_position:current_position + block_size]
        encrypted_blocks.append(encrypted_block)
        current_position += block_size  # Atualiza a posição para o próximo bloco
    
    # Descriptografar o primeiro bloco com a primeira chave
    first_encrypted_block = encrypted_blocks[0]
    first_decrypted_block = combined_decrypt(first_encrypted_block, swap_keys[0], xor_keys[0])
    
    return first_decrypted_block

# Função para rodar o ataque de força bruta para n >= 1
def brute_force_decrypt(final_encrypted, block_size, n):
    i = 0
    # Gerar permutações e combinações de chaves para n swap_keys e n xor_keys
    for swap_keys in itertools.product(itertools.permutations(range(block_size)), repeat=n):
        swap_keys = [bytearray(swap_key) for swap_key in swap_keys]

        for xor_keys in itertools.product(itertools.product(range(256), repeat=block_size)):
            xor_keys = [bytearray(xor_key) for xor_key in xor_keys]
            i += 1

            try:
                # Tenta descriptografar usando a função provided.
                decrypted_block = separate_and_decrypt_first(final_encrypted, swap_keys, xor_keys, block_size)
                decrypted_text = decrypted_block.decode()

                if 'Hey' in decrypted_text:
                    gc.collect()  # Coleta de lixo
                    print(f"Chave correta encontrada! swap_keys: {swap_keys}, xor_keys: {xor_keys}")
                    return swap_keys, xor_keys  # Retorna as chaves corretas ao encontrar o texto

            except UnicodeDecodeError:
                continue
    return None, None  # Se nenhuma chave foi encontrada

# Função para executar o ataque iterativo e registrar o tempo e o valor de n
def run_brute_force_for_different_n(data, max_n, block_size):
    results = []

    for n in range(1, max_n + 1):
        elapsed_times = []
        found_any = False  # Flag para determinar se alguma chave foi encontrada

        for _ in range(5):  # Executa 5 vezes para cada valor de n
            swap_keys, xor_keys = generate_keys(n, block_size, block_size)
            final_encrypted = encrypt_with_multiple_keys(data, swap_keys, xor_keys)

            start_time = time.time()
            swap_keys_found, xor_keys_found = brute_force_decrypt(final_encrypted, block_size, n)
            end_time = time.time()

            elapsed_time = end_time - start_time
            elapsed_times.append(elapsed_time)

            # Verifica se alguma chave foi encontrada
            if swap_keys_found is not None:
                found_any = True  # Sinaliza que a chave correta foi encontrada
            gc.collect()  # Coleta de lixo após cada execução

        # Calcula a média dos tempos para as 5 execuções
        average_time = sum(elapsed_times) / len(elapsed_times)

        # Salva o valor de n, o tempo médio e a flag de se a chave foi encontrada
        result_entry = {
            'n': n,
            'average_elapsed_time': average_time,
            'encontrado': found_any  # Flag para indicar se a chave correta foi encontrada
        }

        results.append(result_entry)
        print(f"Média de tempo para n = {n}: {average_time} segundos, encontrado: {found_any}")

    # Escreve os resultados em um arquivo JSON
    with open('brute_force_results_teste4.json', 'w') as json_file:
        json.dump(results, json_file, indent=4)

    print("Resultados salvos em 'brute_force_results_teste3.json'")

# Dado original para criptografar
data = b'Hey'

# Tamanho do bloco de criptografia
block_size = len(data)

# Número máximo de chaves para testar
max_n = 4

# Executar o ataque iterativo
run_brute_force_for_different_n(data, max_n, block_size)

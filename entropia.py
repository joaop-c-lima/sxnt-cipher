import json
import secrets
from collections import Counter
import math

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

# Exemplo de uso: Gerar 5 swap_keys e 5 xor_keys
#n = 10  # Número de chaves
#swap_key_length = 4  # Tamanho da swap_key
#xor_key_length = 10  # Tamanho da xor_key
block_size = len(b'Hello, World!')  # Tamanho do bloco original a ser criptografado

# Configurações do ataque de força bruta
swap_key_length = block_size  # Tamanho da swap_key
xor_key_length = block_size  # Tamanho da xor_key
n = 10

# Dado original para criptografar
data = b'Hello, World!'

swap_keys, xor_keys = generate_keys(n, swap_key_length, xor_key_length)

# Aplicar a criptografia em cascata e concatenar o resultado
final_encrypted = encrypt_with_multiple_keys(data, swap_keys, xor_keys)

# Exibir o resultado final
print("Resultado Final Concatenado:", final_encrypted)

# Separar os blocos e descriptografar o primeiro
first_decrypted = separate_and_decrypt_first(final_encrypted, swap_keys, xor_keys, block_size)

# Exibir o texto descriptografado
print("Primeiro Texto Descriptografado:", first_decrypted)
print(first_decrypted.decode())
print('Hello' in first_decrypted.decode())

# Função para calcular a entropia
def calculate_entropy(data):
    counter = Counter(data)  # Conta a frequência de cada byte
    total_len = len(data)     # Tamanho total dos dados
    entropy = 0.0

    for count in counter.values():
        p_x = count / total_len  # Probabilidade de ocorrência de cada byte
        entropy += -p_x * math.log2(p_x)  # Soma a entropia de cada byte
    
    return entropy

    
results = []

# Loop para valores de n de 1 até 20, rodando 10 vezes para cada n
for n in range(1, 21):
    entropies = []
    for _ in range(10):  # Executa o teste 10 vezes para cada valor de n
        swap_keys, xor_keys = generate_keys(n, block_size, block_size)
        final_encrypted = encrypt_with_multiple_keys(data, swap_keys, xor_keys)
        entropy_value = calculate_entropy(final_encrypted)
        entropies.append(entropy_value)
    avg_entropy = sum(entropies) / len(entropies)  # Média das entropias
    result = {
        'n': n,
        'avg_entropy': avg_entropy
    }

    results.append(result)

# Escreve os resultados em um arquivo JSON
with open('entropia100.json', 'w') as json_file:
    json.dump(results, json_file, indent=4)

print("Entropia dos dados criptografados:", calculate_entropy(final_encrypted))

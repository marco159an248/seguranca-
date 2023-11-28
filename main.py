import random
import string

def gerar_senha(tamanho, caracteres=None, permitir_repeticao=False):
    if caracteres is None:
        caracteres = string.ascii_letters + string.digits + string.punctuation

    if not permitir_repeticao:
        caracteres = list(set(caracteres))

    senha = ''.join(random.choice(caracteres) for _ in range(tamanho))
    return senha

def remover_caracteres_ambiguos(senha):
    caracteres_ambiguos = 'Il1O0'
    for c in caracteres_ambiguos:
        senha = senha.replace(c, '')
    return senha

def gerar_senhas_qtd(tamanho, quantidade, caracteres=None, permitir_repeticao=False, remover_ambiguos=False):
    senhas = []
    for _ in range(quantidade):
        senha = gerar_senha(tamanho, caracteres, permitir_repeticao)
        if remover_ambiguos:
            senha = remover_caracteres_ambiguos(senha)
        senhas.append(senha)
    return senhas

def definir_opcoes_caracteres():
    opcoes_caracteres = {
        '1': string.ascii_lowercase,
        '2': string.ascii_uppercase,
        '3': string.digits,
        '4': string.punctuation,
    }
    caracteres = ''
    print("Escolha os tipos de caracteres para a senha:")
    print("1 - Letras minúsculas")
    print("2 - Letras maiúsculas")
    print("3 - Dígitos")
    print("4 - Caracteres especiais")
    opcao = input("Digite o número da opção desejada (separado por vírgulas para múltiplas opções): ")
    opcao = opcao.replace(' ', '')
    for o in opcao:
        if o in opcoes_caracteres:
            caracteres += opcoes_caracteres[o]
    return caracteres

def definir_opcoes_avancadas():
    permitir_repeticao = input("Deseja permitir caracteres repetidos? (s/n): ").lower().startswith('s')
    remover_ambiguos = input("Deseja remover caracteres ambíguos (I, l, 1, O, 0)? (s/n): ").lower().startswith('s')
    return permitir_repeticao, remover_ambiguos

def imprimir_senhas(senhas):
    print("Senhas geradas:")
    for senha in senhas:
        print(senha)

def salvar_senhas_arquivo(senhas, nome_arquivo):
    with open(nome_arquivo, 'w') as arquivo:
        for senha in senhas:
            arquivo.write(senha + '\n')
    print("As senhas foram salvas no arquivo", nome_arquivo)

def executar_gerador_senhas():
    continuar = True
    while continuar:
        tamanho_senha = int(input("Digite o tamanho da senha desejada: "))
        quantidade_senhas = int(input("Digite a quantidade de senhas desejada: "))

        caracteres_opcionais = definir_opcoes_caracteres()

        permitir_repeticao, remover_ambiguos = definir_opcoes_avancadas()

        senhas_geradas = gerar_senhas_qtd(tamanho_senha, quantidade_senhas, caracteres_opcionais, permitir_repeticao, remover_ambiguos)

        imprimir_senhas(senhas_geradas)

        deseja_salvar = input("Deseja salvar as senhas em um arquivo? (s/n): ")
        if deseja_salvar.lower().startswith('s'):
            nome_arquivo = input("Digite o nome do arquivo para salvar as senhas: ")
            salvar_senhas_arquivo(senhas_geradas, nome_arquivo)

        opcao_continuar = input("Deseja gerar mais senhas? (s/n): ")
        if not opcao_continuar.lower().startswith('s'):
            continuar = False

executar_gerador_senhas()
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import secrets

def generate_salt():
    return secrets.token_bytes(16)

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return urlsafe_b64encode(key)

def encrypt_message(message, password):
    salt = generate_salt()
    key = generate_key(password, salt)
    cipher_suite = Fernet(key)
    encrypted_message = cipher_suite.encrypt(message.encode())
    return encrypted_message, salt, key

def decrypt_message(encrypted_message, password, salt):
    key = generate_key(password, salt)
    cipher_suite = Fernet(key)
    decrypted_message = cipher_suite.decrypt(encrypted_message)
    return decrypted_message.decode()

def save_to_file(filename, content):
    with open(filename, "wb") as file:
        file.write(content)

def read_from_file(filename):
    with open(filename, "rb") as file:
        content = file.read()
    return content

# Loop infinito para criptografar, descriptografar e outras operações
while True:
    print("1. Criptografar mensagem")
    print("2. Descriptografar mensagem")
    print("3. Salvar mensagem criptografada em arquivo")
    print("4. Ler mensagem criptografada de arquivo")
    print("5. Sair")

    choice = input("Escolha uma opção: ")

    if choice == "1":
        password = input("Digite a senha: ").encode()
        message = input("Digite a mensagem a ser criptografada: ")
        encrypted, salt, key = encrypt_message(message, password)
        print(f"Mensagem criptografada: {encrypted.decode()}")
        print(f"Salt: {salt}")
        print(f"Chave: {key.decode()}\n")

    elif choice == "2":
        password = input("Digite a senha: ").encode()
        encrypted = input("Digite a mensagem criptografada: ")
        salt = input("Digite o salt: ")
        decrypted = decrypt_message(encrypted.encode(), password, salt.encode())
        print(f"Mensagem descriptografada: {decrypted}\n")

    elif choice == "3":
        filename = input("Digite o nome do arquivo para salvar a mensagem criptografada: ")
        password = input("Digite a senha: ").encode()
        message = input("Digite a mensagem a ser criptografada: ")
        encrypted, salt, _ = encrypt_message(message, password)
        save_to_file(filename, encrypted)
        print(f"Mensagem criptografada salva em '{filename}'\n")

    elif choice == "4":
        filename = input("Digite o nome do arquivo para ler a mensagem criptografada: ")
        password = input("Digite a senha: ").encode()
        encrypted = read_from_file(filename)
        salt = input("Digite o salt: ")
        decrypted = decrypt_message(encrypted, password, salt)
        print(f"Mensagem descriptografada: {decrypted}\n")

    elif choice == "5":
        break

    else:
        print("Opção inválida. Tente novamente.\n")
import hashlib
import os

def calcular_hash(texto):
    # Cria um objeto hash SHA-256
    hash_obj = hashlib.sha256()
    
    # Atualiza o objeto hash com o texto fornecido
    hash_obj.update(texto.encode('utf-8'))
    
    # Retorna o valor do hash em formato hexadecimal
    return hash_obj.hexdigest()

def gerar_salt():
    # Gera um valor de salt aleatório
    salt = os.urandom(16)
    
    # Retorna o salt em formato hexadecimal
    return salt.hex()

def calcular_hash_salted(texto, salt):
    # Concatena o salt ao texto
    texto_salt = texto + salt
    
    # Calcula o hash usando SHA-256
    hash_obj = hashlib.sha256()
    hash_obj.update(texto_salt.encode('utf-8'))
    hash_resultante = hash_obj.hexdigest()
    
    # Retorna o hash e o salt utilizado
    return hash_resultante, salt

def verificar_senha(texto, hash_armazenado, salt):
    # Calcula o hash da senha fornecida usando o mesmo salt
    hash_calculado, _ = calcular_hash_salted(texto, salt)
    
    # Compara o hash calculado com o hash armazenado
    return hash_calculado == hash_armazenado

# Exemplo de uso
senha_original = input("Digite a senha original: ")

if senha_original.strip() == "":
    print("Senha vazia. Tente novamente.")
    exit()

salt = gerar_salt()
hash_senha, _ = calcular_hash_salted(senha_original, salt)

print("Senha original:", senha_original)
print("Salt utilizado:", salt)
print("Hash resultante:", hash_senha)

# Verificar a senha
senha_digitada = input("Digite a senha para verificar: ")

if senha_digitada.strip() == "":
    print("Senha vazia. Tente novamente.")
    exit()

if verificar_senha(senha_digitada, hash_senha, salt):
    print("Senha correta.")
else:
    print("Senha incorreta.")

print("Fim do programa")
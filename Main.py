import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Путь для хранения ключа шифрования
KEY_FILE = 'aes_key.key'

def generate_key():
    """Генерация и сохранение ключа AES."""
    key = get_random_bytes(32)  # Используем AES-256 (32 байта ключа)
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    print(f'Ключ сгенерирован и сохранен в файле {KEY_FILE}.')

def load_key():
    """Загрузка ключа AES из файла."""
    if not os.path.exists(KEY_FILE):
        print('Файл с ключом не найден. Генерация нового ключа.')
        generate_key()
    with open(KEY_FILE, 'rb') as f:
        key = f.read()
    return key

def encrypt_file(input_file, output_file):
    """Шифрование файла с использованием AES."""
    key = load_key()
    cipher = AES.new(key, AES.MODE_EAX)
    with open(input_file, 'rb') as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # Сохраняем nonce, тег и шифротекст
    with open(output_file, 'wb') as f:
        [ f.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    print(f'Файл {input_file} успешно зашифрован и сохранен как {output_file}.')

def decrypt_file(input_file, output_file):
    """Дешифрование файла с проверкой целостности."""
    key = load_key()
    with open(input_file, 'rb') as f:
        nonce, tag, ciphertext = [ f.read(x) for x in (16, 16, -1) ]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
        with open(output_file, 'wb') as f:
            f.write(data)
        print(f'Файл {input_file} успешно расшифрован и сохранен как {output_file}.')
    except ValueError:
        print('Неверный ключ или поврежденные данные! Расшифровка не удалась.')

def calculate_hash(filename):
    """Вычисление хеша файла для проверки целостности."""
    h = hashlib.sha256()
    with open(filename, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def verify_integrity(original_file, decrypted_file):
    """Сравнение хешей оригинального и расшифрованного файлов."""
    original_hash = calculate_hash(original_file)
    decrypted_hash = calculate_hash(decrypted_file)
    if original_hash == decrypted_hash:
        print('Целостность файлов подтверждена. Хеши совпадают.')
    else:
        print('Целостность файлов не подтверждена! Хеши не совпадают.')

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='AES шифрование/дешифрование файлов.')
    parser.add_argument('operation', choices=['encrypt', 'decrypt', 'generate_key'], help='Операция: encrypt или decrypt')
    parser.add_argument('input_file', nargs='?', help='Входной файл')
    parser.add_argument('output_file', nargs='?', help='Выходной файл')
    args = parser.parse_args()

    if args.operation == 'generate_key':
        generate_key()
    elif args.operation == 'encrypt':
        if not args.input_file or not args.output_file:
            print('Пожалуйста, укажите входной и выходной файлы для шифрования.')
        else:
            encrypt_file(args.input_file, args.output_file)
    elif args.operation == 'decrypt':
        if not args.input_file or not args.output_file:
            print('Пожалуйста, укажите входной и выходной файлы для дешифрования.')
        else:
            decrypt_file(args.input_file, args.output_file)
            # Проверка целостности
            original_file = input('Введите имя оригинального файла для проверки целостности: ')
            if 
          os. path. exists(original_file):
            verify_integrity(original_file, args.output_file)
            else:
                print('Оригинальный файл не найден. Проверка целостности невозможна.')



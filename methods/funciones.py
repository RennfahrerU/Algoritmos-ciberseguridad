import os
import json
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import getpass
from Crypto.Protocol.KDF import PBKDF2

# Variables
USUARIOS_JSON = "usuarios.json" # Almacenamiento de los usuarios con salting
SALT_SIZE = 16  # Tamaño del salt para derivación de claves

# Cargar o crear archivo de usuarios
def cargar_usuarios():
    """
    Carga los usuarios desde un archivo JSON. Si no existe, lo crea.
    :return: Lista de usuarios.
    """
    if not os.path.exists(USUARIOS_JSON):
        with open(USUARIOS_JSON, 'w') as f: # Lo crea si no existe
            json.dump([], f)
    with open(USUARIOS_JSON, 'r') as f:
        return json.load(f) # Carga si lo encuentra

# Guardar usuarios en el archivo JSON
    """
    Guarda usuarios mediante dumping en usuarios.JSON.
    :param usuarios: Datos del usuario a guardar.
    """
def guardar_usuarios(usuarios):
    with open(USUARIOS_JSON, 'w') as f:
        json.dump(usuarios, f, indent=4)

def derivar_clave(password, salt):
    """
    Deriva una clave segura a partir de una contraseña y un salt usando PBKDF2.
    :param password: Contraseña en texto plano.
    :param salt: Valor aleatorio único.
    :return: Clave de 24 bytes para 3DES.
    """
    return PBKDF2(password, salt, dkLen=24, count=100000)

# Cifrar datos con 3DES (en modo CBC)
def cifrar_datos(dato, clave):
    """
    Cifra los datos sensibles usando 3DES en modo CBC.
    :param dato: Datos sensibles en texto plano.
    :param clave: Clave de 24 bytes para 3DES (3 claves de 8 bytes cada una).
    :return: Datos cifrados concatenados con el IV.
    """
    iv = get_random_bytes(8) # Vector de inicialización
    cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    dato_padded = pad(dato.encode('utf-8'), DES3.block_size)
    datos_cifrados = cipher.encrypt(dato_padded)
    return iv + datos_cifrados 

# Descifrar datos con 3DES
def descifrar_datos(dato_cifrado, clave):
    """
    Descifra los datos cifrados con 3DES en modo CBC.
    :param dato_cifrado: Datos cifrados incluyendo el IV.
    :param clave: Clave de 24 bytes para descifrar.
    :return: Datos descifrados en texto plano.
    """
    iv = dato_cifrado[:8]  # Extraer IV
    datos_cifrados = dato_cifrado[8:]  # Datos cifrados
    cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    dato_descifrado = unpad(cipher.decrypt(datos_cifrados), DES3.block_size)
    return dato_descifrado.decode('utf-8')

# Cifrar archivo
def cifrar_archivo(ruta_archivo, clave, salt):
    """
    Cifra un archivo de texto y lo guarda con la extensión '.encrypted'.
    :param ruta_archivo: Ruta del archivo original.
    :param clave: Clave de 24 bytes para el cifrado.
    :param salt: Salt aleatorio usado para derivar la clave.
    :return: True si el cifrado es exitoso, False en caso de error.
    """
    try:
        with open(ruta_archivo, 'r') as f:
            contenido = f.read()
        contenido_cifrado = cifrar_datos(contenido, clave) # Guardar salt + datos cifrados en formato base64
        with open(ruta_archivo + '.encrypted', 'w') as f:
            f.write(base64.b64encode(salt + contenido_cifrado).decode('utf-8'))
        return True
    except Exception as e:
        print(f"Error al cifrar: {str(e)}")
        return False

# Descifrar archivo
def descifrar_archivo(ruta_archivo, clave):
    """
    Descifra un archivo cifrado y lo guarda con la extensión '.decrypted'.
    :param ruta_archivo: Ruta del archivo cifrado.
    :param clave: Contraseña original utilizada para derivar la clave.
    :return: True si el descifrado es exitoso, False en caso de error.
    """
    try:
        with open(ruta_archivo, 'r') as f:
            contenido_cifrado = base64.b64decode(f.read())
        salt = contenido_cifrado[:SALT_SIZE]  # Extraer salt
        contenido_cifrado = contenido_cifrado[SALT_SIZE:]  # Datos cifrados
        clave_verificada = derivar_clave(clave.encode('utf-8'), salt)  # Regenerar clave
        contenido_descifrado = descifrar_datos(contenido_cifrado, clave_verificada)
        with open(ruta_archivo.replace('.encrypted', '.decrypted'), 'w') as f:
            f.write(contenido_descifrado)
        return True
    except Exception as e:
        print(f"Error al descifrar: {str(e)}")
        return False

# Autenticar usuario
def autenticar_usuario():
    """
    Autentica a un usuario verificando su contraseña con PBKDF2.
    :return: Usuario autenticado o None si la autenticación falla.
    """
    usuarios = cargar_usuarios()
    username = input("Usuario: ")
    password = getpass.getpass("Contraseña: ")
    for usuario in usuarios:
        if usuario['username'] == username:
            salt = base64.b64decode(usuario['salt'])
            clave_derivada = derivar_clave(password.encode('utf-8'), salt)
            if usuario['clave'] == base64.b64encode(clave_derivada).decode('utf-8'):
                return usuario
    return None

# Crear nuevo usuario (solo para administradores)
def crear_usuario():
    """
    Crea un nuevo usuario con autenticación basada en PBKDF2 y lo almacena en JSON.
    """
    usuarios = cargar_usuarios()
    username = input("Nuevo usuario: ")
    password = getpass.getpass("Nueva contraseña: ")
    es_admin = input("¿Es administrador? (s/n): ").lower() == 's'
    salt = get_random_bytes(SALT_SIZE)
    clave_derivada = derivar_clave(password.encode('utf-8'), salt)
    usuarios.append({
        'username': username,
        'clave': base64.b64encode(clave_derivada).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8'),
        'es_admin': es_admin
    })
    guardar_usuarios(usuarios)
    print("Usuario creado exitosamente.")
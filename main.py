from methods.funciones import *

def menu_principal():
    print("\n--- Sistema de Cifrado 3DES ---")
    print("1. Cifrar archivo")
    print("2. Descifrar archivo")
    print("3. Crear usuario")
    print("4. Salir")
    return input("Seleccione una opción: ")

def main():
    # crear_usuario()  # Descomentar para crear un usuario
    usuario = autenticar_usuario()
    if not usuario:
        print("Autenticación fallida.")
        return

    while True:
        # Verificar usuario como admin y darle acceso total
        if usuario['es_admin']:
            opcion = menu_principal()
        else:
            opcion = '2'  

        # Opción visible si el usuario es administrador
        if opcion == '1' and usuario['es_admin']:
            ruta = input("Ruta del archivo que se va a cifrar: ")
            password = getpass.getpass("Contraseña para derivar la clave: ")
            salt = get_random_bytes(SALT_SIZE)
            clave = derivar_clave(password.encode('utf-8'), salt)
            if cifrar_archivo(ruta, clave, salt):
                print("Archivo cifrado exitosamente.")
        
        # Única opción si el usuario no es administrador
        elif opcion == '2':
            ruta = input("Ruta del archivo cifrado (.encrypted), dejar vacio para salir: ")
            if not ruta:
                break
            password = getpass.getpass("Contraseña para derivar clave: ")
            if descifrar_archivo(ruta, password):
                print("Archivo descifrado exitosamente.")
        
        elif opcion == '3':
            crear_usuario()
        elif opcion == '4':
            break
        else:
            print("Opción no válida.")

if __name__ == "__main__":
    main()
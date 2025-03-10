## Algoritmo 3DES

### Utiliza el algoritmo 3DES para cifrar y descifrar datos dentro del sistema. Desarrolla el  siguiente flujo: 

#### Cifrado de Datos Sensibles: 
El sistema debe permitir a los empleados con privilegios específicos cifrar datos 
sensibles (por ejemplo, información financiera o detalles de clientes). 

Los datos cifrados deben almacenarse de manera segura, y solo los usuarios 
autorizados con la clave correcta deben poder acceder a ellos. 

#### Descifrado de Datos: 
Solo los usuarios autorizados, mediante contraseña, deben tener acceso para descifrar 
y visualizar los datos sensibles. 

### Uso del aplicativo

#### Biblitecas Requeridas

Están especificadas en requirements.txt para comodidad con entornos virtuales.

#### Usuarios incluidos por defecto:

1) admin:admin
2) usuario:usuario

#### Workflow

Al inicializar la aplicación, se presenta un menú principal con las siguientes opciones:

1. Iniciar sesión: Permite a los usuarios autenticarse ingresando su nombre de usuario y contraseña. Se utiliza PBKDF2 para verificar la clave de manera segura.
2. Crear usuario (solo para administradores): Opción que permite registrar nuevos usuarios en el sistema con un nombre de usuario, una contraseña cifrada y un indicador de permisos administrativos.
3. Cifrar archivo (solo para administradores): Permite seleccionar un archivo de texto para cifrar su contenido usando el algoritmo 3DES.
4. Descifrar archivo: Opción para seleccionar un archivo previamente cifrado y restaurarlo a su estado original.
5. Salir: Finaliza la ejecución del programa.

Al seleccionar una opción, se solicita la información correspondiente y se ejecuta la función asociada. El flujo principal del programa se mantiene en un bucle hasta que el usuario elija salir.

## Estructura de carpetas
```
    └── 📁methods
        └── funciones.py
    └── 📁resources
        └── archivo.txt
        └── archivo.txt.decrypted
        └── archivo.txt.encrypted
    └── main.py
    └── README.md
    └── requirements.txt
    └── usuarios.json
```

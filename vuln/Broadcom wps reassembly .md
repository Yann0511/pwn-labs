# Faille Wi-Fi Broadcom — débordement au réassemblage WPS

> Analyse pédagogique d'une vulnérabilité **divulguée publiquement**, à des fins d'apprentissage et de défense.
> Vulgarisation d'après la recherche de **Quentin Kaiser** (« One Parser, Two Bugs, Many Routers », Hexacon, 16 octobre 2026).
> Aucun exploit armé n'est fourni : seulement le mécanisme, le modèle de menace et les contre-mesures.

| | |
|---|---|
| **Type** | Débordement de tampon au réassemblage WPS/EAP → exécution de code |
| **Composant** | Implémentation **propriétaire Broadcom** du WPS (firmware Wi-Fi) |
| **Accès** | **Pré-authentification**, par radio (sans la clé Wi-Fi), à distance |
| **Portée** | Deux familles de puces : **eCos** (BCM3380/3383…) et **Linux** (BCM3390/65xx/68xx) |
| **Appareils** | Nombreuses box/routeurs Broadcom ; en Belgique : Proximus, VOO, Orange Belgium. Modèles français (Livebox, SFR) évoqués par la presse |
| **Historique** | Présent depuis **~2010** · correctif **incomplet en 2018** · **aucun CVE attribué** |
| **Divulgation** | Hexacon (Paris), 16 octobre 2026 — au 15/10, aucun appareil corrigé |

---

## 1. Contexte — le WPS répond avant l'authentification

Le **WPS** (*Wi-Fi Protected Setup*) permet de connecter un appareil au Wi-Fi « par bouton », sans saisir la clé. Pour cela, la puce Wi-Fi **traite des messages d'un appareil qui n'est pas encore authentifié** : c'est une surface d'attaque ouverte à toute personne **à portée radio**.

Ce code WPS est l'**implémentation propriétaire de Broadcom**, embarquée dans le firmware de millions de box et routeurs — sur deux plateformes de puces, **eCos** et **Linux**. Un même parseur fautif, donc un même bug, se retrouve partout (« One Parser, Two Bugs »).

## 2. La vulnérabilité — un réassemblage mal borné

Les messages WPS/EAP peuvent arriver **fragmentés** (en plusieurs morceaux). Le firmware doit les **réassembler** dans un tampon avant de les traiter. Le bug : le réassemblage **ne vérifie pas la taille totale** des fragments par rapport à la capacité du tampon. Un message fragmenté **forgé** fait dépasser le tampon → **débordement mémoire**, puis **exécution de code** dans le firmware de la puce.

> C'est exactement le motif enseigné dans [les labs de ce repo](../) : une écriture dont la taille dépend d'une entrée non validée. Ici, le contexte est un firmware embarqué, atteignable par radio.

### Le motif, en miniature (illustration, pas le code réel de Broadcom)

```c
/* ✗ VULNÉRABLE — on copie chaque fragment sans compter */
uint8_t buf[256];              // tampon de taille fixe
size_t  off = 0;
for (frag in fragments) {      // messages WPS en morceaux
    memcpy(buf + off, frag.data, frag.len);
    off += frag.len;           // <-- off dépasse 256 : déborde
}

/* ✓ CORRIGÉ — on refuse ce qui dépasse le tampon */
uint8_t buf[256];
size_t  off = 0;
for (frag in fragments) {
    if (off + frag.len > sizeof(buf))   // <-- borne
        return ERROR;                   // on rejette
    memcpy(buf + off, frag.data, frag.len);
    off += frag.len;
}
```

## 3. Le danger réel — pire qu'un overflow « classique »

- **À portée radio** : pas besoin d'accès au réseau, seulement d'être à proximité.
- **Avant toute authentification** : la clé Wi-Fi ne protège pas — l'attaque passe *avant* elle. Changer son mot de passe ne sert à rien.
- **Fuite de la clé** : le chercheur a démontré l'extraction de la PSK Wi-Fi depuis la mémoire (NVRAM).
- **Exécution de code sur la box** : shell root, reverse shell transmis dans des trames 802.11. Contrôler le routeur, c'est tenir la porte d'entrée de tout le réseau.

## 4. La chaîne (conceptuelle)

```
Attaquant à portée radio  (aucune clé, aucun compte)
      ▼
Envoie un message WPS fragmenté forgé  (traité avant authentification)
      ▼
Le firmware le réassemble mal  → débordement du tampon
      ▼
Exécution de code sur la puce Wi-Fi  (shell root / reverse shell, 802.11)
      ▼
Contrôle de la box + clé Wi-Fi volée  → point d'entrée du réseau
```

> Ce writeup s'arrête au **concept**. Les détails d'exploitation armée ne sont pas fournis.

## 5. L'angle mort — 16 ans, un demi-correctif, aucun CVE

- Bug introduit **~2010**, correctif **incomplet et silencieux en 2018**, toujours exploitable en 2026.
- **Aucun CVE** : Broadcom a refusé d'en attribuer un. Comme Broadcom est lui-même **CNA** (autorité d'attribution de CVE), le dossier CERT/CC a été clos.
- Broadcom recommande aux fabricants de **migrer vers `hostapd`** (l'implémentation open-source), mais la migration incombe à chaque OEM.

**Conséquence :** sans CVE, pas de suivi centralisé. Chaque fabricant et chaque opérateur corrige — ou pas — dans son coin, et c'est l'utilisateur final qui porte le risque. C'est un cas d'école de **gouvernance des vulnérabilités**, autant que de technique.

## 6. Se protéger

1. **Désactiver le WPS** si on ne s'en sert pas — réduit la surface, sans garantie totale.
2. **Appliquer les mises à jour** de la box ; surveiller les annonces de l'opérateur (déploiement automatique, en principe).
3. **Couper le Wi-Fi de la box et passer en Ethernet** — radical, mais efficace : plus de radio vulnérable à l'écoute.
4. **Box en bridge + son propre routeur** *(utilisateur avancé)* : mettre la box en mode modem seul, **Wi-Fi de la box coupé**, et gérer le Wi-Fi avec un routeur sous **OpenWrt / `hostapd`**. C'est la mitigation la plus robuste — mais elle ne protège **que si la radio Wi-Fi de la box est réellement désactivée**, et à condition que le routeur de remplacement n'embarque pas lui-même une puce Broadcom WPS vulnérable (sinon le problème est seulement déplacé). À noter : cette approche revient exactement au correctif recommandé par Broadcom (`hostapd`).
5. **Côté fabricant** (le vrai correctif) : **borner le réassemblage** et migrer vers `hostapd`.

> L'utilisateur ne peut que réduire la surface d'attaque ; la correction de fond est entre les mains des fabricants.

## 7. Pourquoi ça compte

L'**embarqué est le maillon faible** de la sécurité : firmware rarement audité, peu mis à jour, cycles de vie longs. Le C bas niveau y est partout, et une faille mémoire peut y **dormir 16 ans**. « Un message mal réassemblé, une mémoire mal gérée » — c'est un *bug de dev*, trouvé par quelqu'un qui sait **lire du code**. Comprendre ces mécanismes, c'est savoir les traquer avant qu'ils ne soient exploités.

---

## Sources

- [Quentin Kaiser — « One Parser, Two Bugs, Many Routers » (source primaire)](https://quentinkaiser.be/security/2026/10/16/one-parser-two-bugs/)
- [Clubic — Faille Wi-Fi critique : des Livebox et box SFR concernées](https://www.clubic.com/actualite-634699-faille-wi-fi-critique-des-livebox-d-orange-et-box-sfr-piratables-sans-mot-de-passe.html)
- [Univers Freebox — couverture de la faille](https://www.universfreebox.com/article/598531/une-faille-wi-fi-permet-de-pirater-des-box-internet-sans-mot-de-passe-des-livebox-dorange-et-des-box-sfr-pourraient-etre-concernees)

---

*Rédigé par Yann Kelly OLOU — dans le cadre de [pwn-labs](../). Vulgarisation d'une recherche publique, à des fins d'apprentissage et de défense.*

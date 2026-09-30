<p align="center">
 <img src="./assets/icon.svg" width="128" />
</p>
<h1 align="center">L92 WebKit Autoloader</h1>
&nbsp;
<p align="center"><b>par L92</b> — d'après <a href="https://github.com/itsPLK/ps5-webkit-autoloader">ps5-webkit-autoloader</a> de itsPLK<br>Charge automatiquement l'exploit WebKit et vos payloads ELF.<br>Supporte les firmwares <b>1.00&ndash;5.50</b> et <b>7.00&ndash;13.60</b>.</p>

<p align="center">
  <a href=".github/screenshots/webkit_autoloader.jpeg"><img src=".github/screenshots/webkit_autoloader.jpeg" width="260" alt="L92 WebKit Autoloader - exploit en cours" /></a>
  <a href=".github/screenshots/webkit_autoloader_installer.jpeg"><img src=".github/screenshots/webkit_autoloader_installer.jpeg" width="260" alt="Installateur" /></a>
</p>

## Pourquoi L92 WebKit Autoloader ?

Les exploits WebKit sont généralement chargés en pointant le DNS de votre PS5 vers un serveur hébergé par quelqu'un sur Internet. Cela signifie que vous accordez votre confiance à la personne qui gère ce serveur — et s'il tombe en panne, change ou disparaît, votre installation est cassée.

Cet autoloader fait différemment :

- **100 % hors ligne, aucun DNS tiers.** Après une installation unique depuis votre PC, tout est servi directement depuis votre PS5. Rien d'externe ne peut tomber en panne ou changer dans votre dos.
- **Configuration unique, puis raccourci sur l'accueil.** Une fois installé, vous n'avez plus besoin de PC ni de réseau — lancez simplement **L92 WebKit Autoloader** depuis l'accueil et c'est parti.
- **Payloads chargés comme vous en avez l'habitude.** Après l'exécution de la chaîne d'exploits, vos payloads sont envoyés via **Payload Manager**, ou via un fichier `autoload.txt` personnalisé.

- **100 % hors ligne (Poops), aucun DNS tiers.** Après une installation unique depuis votre PC, tout est servi directement depuis votre PS5. Rien d'externe ne peut tomber en panne ou changer dans votre dos.  
  Poops fonctionne **entièrement hors ligne**. Relapse (firmwares 12.02–13.60) nécessite une interface réseau active (Wi-Fi ou Ethernet reliés à un réseau local ; l'accès à Internet n'est pas requis).
- **Configuration unique, puis raccourci sur l'accueil.** Une fois installé, vous n'avez plus besoin de PC ni de réseau — lancez simplement **L92 WebKit Autoloader** depuis l'accueil et c'est parti.
- **Payloads chargés comme vous en avez l'habitude.** Après l'exécution de la chaîne d'exploits, vos payloads sont envoyés comme dans les autoloaders [Y2JB](https://github.com/itsPLK/ps5-y2jb-autoloader) / [BD-JB](https://github.com/itsPLK/ps5-bdjb-autoloader) / [Lua](https://github.com/itsPLK/ps5-lua-autoloader) — via **Payload Manager**, ou un fichier `autoload.txt` personnalisé.


## Instructions d'installation

Deux méthodes selon que votre console est déjà jailbreakée ou non.

### Déjà jailbreaké ? Chargez simplement l'ELF d'installation

1. Téléchargez `webkit-autoloader-installer_vX.Y.Z.elf` depuis la page [Releases](https://github.com/lamine5656/ps5-webkit-autoloader/releases).
2. Envoyez-le à votre PS5 avec `elfldr`, ou lancez-le depuis Payload Manager.
3. L'installateur ouvre le navigateur une fois pour mettre en cache la page de l'autoloader, crée l'application **L92 WebKit Autoloader** sur l'accueil, puis se ferme.
4. **Redémarrez une fois**, puis lancez **L92 WebKit Autoloader** depuis l'accueil.

### Pas encore jailbreaké

Si votre console n'est pas encore jailbreakée, vous devrez héberger l'exploit localement sur votre PC pour la configuration initiale :

1. Téléchargez `webkit-autoloader-host.py` (ou le `.exe`) depuis les [Releases](https://github.com/lamine5656/ps5-webkit-autoloader/releases) et lancez-le sur un PC de votre réseau.
2. Sur votre PS5, réglez le DNS de votre réseau sur l'adresse IP de votre PC.
3. Ouvrez le **Guide de l'utilisateur** depuis les Paramètres pour lancer l'installateur, qui ajoute l'application **L92 WebKit Autoloader** à l'accueil.
4. Lancez **L92 WebKit Autoloader** depuis l'accueil.

## Utilisation

Deux façons de configurer les payloads :

### 🟢 Option 1 : Payload Manager

Si aucun fichier `autoload.txt` n'est trouvé, l'autoloader lance automatiquement **[Payload Manager](https://github.com/itsPLK/ps5-payload-manager)** — un gestionnaire de payloads PS5 complet avec interface web. Cela permet d'envoyer et de configurer vos payloads directement depuis votre navigateur, sans fichier de configuration ni transfert manuel d'ELF.

Lancez simplement l'autoloader — s'il n'y a rien de configuré, Payload Manager démarre automatiquement.

> **Remarque :** Payload Manager possède aussi son propre système d'autoload intégré, configurable via son interface web. Il est indépendant du mécanisme `autoload.txt` décrit ci-dessous.

---

### ⚙️ Option 2 : Configuration manuelle (`autoload.txt`)

Pour une chaîne de payloads fixe et automatisée :

- Créez un dossier nommé `ps5_autoloader`.
- Placez-y vos fichiers `.elf` / `.bin` ainsi qu'un fichier `autoload.txt`.
  - Dans `autoload.txt`, listez les fichiers à charger, un nom par ligne.
  - Les noms sont sensibles à la casse — assurez-vous qu'ils correspondent exactement.
  - Vous pouvez ajouter des lignes comme `!1000` pour attendre 1000 ms avant d'envoyer le payload suivant.
- Placez le dossier `ps5_autoloader` à l'un de ces emplacements (par priorité décroissante) :
  - Racine d'une clé USB
  - Disque interne : `/data/ps5_autoloader`

> **Remarque :** lorsqu'un `autoload.txt` est trouvé, Payload Manager **n'est pas** lancé automatiquement. Si vous voulez aussi Payload Manager, placez `pldmgr.elf` dans votre dossier `ps5_autoloader` et ajoutez-le à `autoload.txt`.

## Infos complémentaires

<Details>
<Summary><i>Comment mettre à jour l'autoloader ?</i></Summary>

Le contenu de l'autoloader est mis en cache sur la console : la mise à jour se fait exactement comme l'installation initiale. Suivez simplement les **[Instructions d'installation](#instructions-dinstallation)** avec les fichiers de la nouvelle version.

Le dernier payload d'installateur recrée l'application de l'accueil et rafraîchit la page en cache. Vos payloads et votre `autoload.txt` sur USB / stockage interne ne sont jamais touchés.
</Details>

<Details>
<Summary><i>Comment utiliser un ELF Loader personnalisé ?</i></Summary>

Sur firmwares 7.00–13.60 (Relapse / Poops), l'autoloader utilise une version personnalisée d'**elfldr** qui n'accepte les connexions que depuis la PS5 elle-même (localhost). Cela améliore la sécurité en empêchant tout appareil non autorisé de votre réseau d'envoyer des payloads à votre console. Sur firmwares 1.00–5.50 (umtx2), l'elfldr d'origine est démarré.

Si vous souhaitez utiliser un ELF Loader « normal » acceptant les payloads de n'importe quel appareil, chargez-le simplement via **Payload Manager**.

Alternativement, avec un fichier de configuration (`autoload.txt`) :
1. Placez votre ELF Loader personnalisé (ex. `elfldr.elf`) dans le dossier `ps5_autoloader`.
2. Ajoutez `elfldr.elf` à votre `autoload.txt`.
3. **Remarque** : si vous chargez d'autres payloads juste après `elfldr.elf` dans votre `autoload.txt`, ajoutez une commande de pause juste après (comme `!4000` pour 4 secondes) pour laisser le nouvel ELF Loader démarrer et écouter avant l'envoi des payloads suivants.

Exemple de `autoload.txt` :
```text
# Charger l'ELF Loader personnalisé
elfldr.elf
# Lui laisser 4 secondes (uniquement si d'autres payloads suivent)
!4000
# Envoyer les autres payloads
etaHEN.elf
```
</Details>

---

## Pour les développeurs

Les détails techniques et l'architecture du projet sont documentés dans **[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Crédits

* **L92** — interface française néon, rebranding et packaging de cette version
* **[itsPLK](https://github.com/itsPLK)** — projet de base [ps5-webkit-autoloader](https://github.com/itsPLK/ps5-webkit-autoloader)
* **[idlesauce](https://github.com/idlesauce)** & contributeurs — [umtx2](https://github.com/idlesauce/umtx2)
* **[jordyidk](https://github.com/jordyidk)** & contributeurs — [slopkit (Poops)](https://github.com/jordyidk/slopkit)
* **[soniciso1](https://github.com/soniciso1)** — support de Poops étendu aux firmwares plus anciens (7.00–8.60)
* **[ntfargo](https://github.com/ntfargo)** & contributeurs — [Relapse](https://github.com/ntfargo/Relapse-Exploit)
* **[john-tornblom](https://github.com/john-tornblom)** — [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk/) et [elfldr](https://github.com/ps5-payload-dev/elfldr)
* **[Mark Adler](https://github.com/madler)** — [puff.c](https://github.com/madler/zlib/tree/master/contrib/puff) (décompression des fichiers frontend embarqués)
* Tous les autres contributeurs de la scène homebrew PS5.

## Avertissement

Cet outil est fourni tel quel, à des fins de recherche et de développement uniquement. Utilisez-le à vos propres risques. Les développeurs ne sont pas responsables de tout dommage, perte de données ou conséquences résultant de l'utilisation de ce logiciel.

## Licence

Ce projet est sous licence GPL-3.0 (comme le projet original de itsPLK).

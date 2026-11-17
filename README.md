# pcap-verifier : interroger un PCAP en français, avec preuves

Un assistant qui répond à des questions sur une capture réseau (PCAP) et
prouve ce qu'il affirme. Projet d'apprentissage en forensique réseau,
100 % gratuit : tshark, Python et un petit modèle local (Ollama).

**Principe : l'IA propose, le code calcule, un vérificateur contrôle.**
Une IA peut inventer un paquet qui n'existe pas. Ici, elle ne produit
aucun chiffre : elle choisit seulement parmi des faits calculés par tshark.

## Comment ça marche

1. L'IA lit la question et choisit une recette dans un menu.
2. tshark calcule des faits sur le fichier (`outil.py`).
3. L'IA désigne un fait par son numéro.
4. Le vérificateur recalcule le fait et le compare (`verif.py`).
5. Le code écrit la réponse, avec les numéros de paquets et les faits voisins.

L'IA ne lance jamais de commande : elle ne peut choisir qu'une recette
du menu. La phrase de réponse est écrite par le code, pas par l'IA.

## Ce qu'il sait faire (8 recettes)

domaines (DNS), sites web, conversations, protocoles, activité d'une
adresse IP, compteurs de paquets (total, envoyés, reçus par machine),
détection de scan de ports, fichiers téléchargés (HTTP).

## Exemple (sortie réelle, fichier de test avec un scan nmap)

    Question : Combien de paquets de sondage y a-t-il eu ?
    Fait choisi par l'IA : ports distincts sondés ... = 100
    VERDICT : PROUVÉE
    Faits voisins, calculés par le code (à lire avant de conclure) :
       paquets de sondage SYN de 192.168.163.128 vers 192.168.163.1 = 200
    -> ports distincts sondés de 192.168.163.128 vers 192.168.163.1 = 100
       scan de ports probable (au moins 15 ports distincts) = oui

L'IA s'est trompée de ligne (100 ports au lieu de 200 paquets de sondage),
mais la bonne réponse est visible juste à côté. C'est voulu.

## Ce que « PROUVÉE » veut dire

**Le fait cité existe dans le fichier.** Cela ne garantit pas qu'il
répond à la question. Lisez toujours les faits voisins.

## Résultats mesurés (honnêtes)

- Banc d'essai : 8 questions écrites par l'auteure, modèle `qwen2.5:1.5b`,
  température 0, deux passages identiques.
  **5/8 correctes et prouvées (62 %)**, 7/8 prouvées, refus des
  questions hors sujet respecté.
- Une version précédente (l'IA recopiait le libellé du fait) donnait 6/8.
  Le passage au choix par numéro supprime les libellés réécrits, mais
  l'IA choisit parfois la mauvaise ligne. Sur 8 questions, l'écart n'est
  pas significatif.
- Sur une quinzaine de questions posées à la main, 4 cas où un fait vrai
  mais hors sujet a été marqué PROUVÉE : 28 confondu avec 26 (total et
  paquets IPv4), reçus confondus avec envoyés (11 et 15), 100 ports
  confondus avec 200 paquets de sondage, et une taille de fichier prise
  pour un code de réponse.

## Limites connues

- Testé sur 3 petits fichiers fabriqués (web et DNS, scan, transfert),
  avec un petit modèle. Aucun gros PCAP testé.
- L'IA se trompe parfois de recette ou de fait. Un seul fait est
  désigné par question, plus 10 faits voisins au maximum.
- « Où suis-je allée ? » est refusée dans le banc (« aucun fait ne
  répond »), alors que la recette contient la bonne ligne.
- Pas de recette ICMP : « y a-t-il eu des pings ? » est refusée.
- Impossible de répondre à « le flux est-il normal ? » ou « y a-t-il
  un changement de comportement ? » : il faut comparer deux fichiers.
- `banc.py` contient les adresses IP de mes captures de test.
- Taille de fichier : c'est la taille annoncée par le serveur, pas la
  taille réellement transférée.

## Installation

- Sur la machine hôte : Ollama et `ollama pull qwen2.5:1.5b`. Le faire
  écouter uniquement sur l'adresse du réseau privé de la VM, puis le
  vérifier (`netstat -ano | findstr 11434`).
- Dans la VM : `sudo apt install tshark python3`, copier
  `outil.py verif.py agent.py banc.py`, adapter `URL` dans `agent.py`.

## Utilisation

    python3 agent.py fichier.pcap     # poser des questions
    python3 verif.py                  # tests du vérificateur (12)
    python3 banc.py                   # banc d'essai

## Sécurité

- Aucune commande libre : le code construit la liste d'arguments de
  tshark, sans `shell=True`.
- N'analysez que des captures que vous avez le droit d'analyser. Ne
  scannez que vos propres machines.
- Ne publiez jamais un PCAP issu d'un cadre professionnel.

## Prochaines étapes

Plusieurs fichiers à la fois, comparaison de deux captures, recette ICMP,
rapport automatique vérifié ligne par ligne.

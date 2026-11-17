import json
import os
import sys
import urllib.request

from outil import RECETTES, executer, run_tshark
from verif import verifier

URL = "http://192.168.163.1:11434/api/generate"
MODELE = "qwen2.5:1.5b"
PCAP = os.path.expanduser(sys.argv[1] if len(sys.argv) > 1 else "~/mon_test.pcap")
JOURNAL = os.path.expanduser("~/journal_agent.txt")
MAX_FAITS = 40

DESCRIPTIONS = {
    "domaines": "quels noms de domaine ont été demandés",
    "sites_web": "quelles pages web ont été demandées",
    "conversations": "qui parle avec qui",
    "protocoles": "quels protocoles sont présents",
    "ip": "que s'est-il passé avec une adresse IP précise (donne l'adresse dans \"ip\")",
    "compteurs": "combien de paquets en tout, et combien chaque adresse a envoyé ou reçu",
    "scan": "y a-t-il eu un scan de ports",
    "fichiers": "quels fichiers ont été demandés ou téléchargés, avec quel code et quelle taille",
}

EXEMPLES = {
    "sites_web": ("quels sites web ont été visités ?", '{"recette": "sites_web", "ip": ""}'),
    "ip": ("que s'est-il passé avec 192.168.1.5 ?", '{"recette": "ip", "ip": "192.168.1.5"}'),
    "compteurs": ("combien de paquets la machine a-t-elle envoyés ?", '{"recette": "compteurs", "ip": ""}'),
    "scan": ("quelqu'un a-t-il scanné des ports ?", '{"recette": "scan", "ip": ""}'),
    "fichiers": ("quel fichier a été téléchargé ?", '{"recette": "fichiers", "ip": ""}'),
}

PROMPT_1 = """Tu choisis une recette d'analyse réseau. Écris son nom exact :
@MENU@
Réponds uniquement en JSON : {"recette": "...", "ip": "..."} ("ip" vide sauf pour la recette ip).
Si aucune recette ne convient, réponds {"recette": "aucune", "ip": ""}.
Exemples :
@EXEMPLES@

Question : @QUESTION@
"""

PROMPT_2 = """Question : @QUESTION@
Voici des faits calculés sur le fichier, numérotés :
@FAITS@

Quel fait répond à la question ? Réponds uniquement en JSON : {"numero": N}
où N est le numéro du fait. Si aucun fait ne répond à la question, réponds {"numero": 0}.
"""


def demander_ia(prompt):
    corps = json.dumps({"model": MODELE, "prompt": prompt,
                        "stream": False, "format": "json",
                        "options": {"temperature": 0, "seed": 42}}).encode()
    req = urllib.request.Request(URL, data=corps,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            texte = json.loads(r.read())["response"]
        resultat = json.loads(texte)
        return resultat if isinstance(resultat, dict) else None
    except Exception as e:
        print("Problème avec l'IA :", e)
        return None


def prompt_recette(question):
    menu = "\n".join("- %s : %s" % (n, DESCRIPTIONS.get(n, n)) for n in RECETTES)
    exemples = "\n".join("Question : %s\n%s" % EXEMPLES[n] for n in RECETTES if n in EXEMPLES)
    return (PROMPT_1.replace("@MENU@", menu)
            .replace("@EXEMPLES@", exemples)
            .replace("@QUESTION@", question))


def prompt_fait(question, faits):
    lignes = []
    for i, fait in enumerate(faits[:MAX_FAITS], start=1):
        lignes.append("%d. %s = %s" % (i, fait["quoi"], fait["valeur"]))
    return PROMPT_2.replace("@QUESTION@", question).replace("@FAITS@", "\n".join(lignes))


def entiers(liste):
    if not isinstance(liste, list):
        return []
    sortie = []
    for x in liste:
        try:
            sortie.append(int(x))
        except (TypeError, ValueError):
            return None
    return sortie


def phrase_finale(quoi, valeur, frames):
    texte = "%s : %s" % (quoi, valeur)
    if frames:
        montres = ", ".join(str(x) for x in frames[:10])
        plus = " (et %d autres)" % (len(frames) - 10) if len(frames) > 10 else ""
        texte += " | preuve : paquets %s%s" % (montres, plus)
    return texte


def noter(question, recette, fiche, verdict):
    try:
        with open(JOURNAL, "a", encoding="utf-8") as f:
            f.write("%s | %s | %s | %s | %s\n"
                    % (os.path.basename(PCAP), question, recette, fiche, verdict))
    except OSError:
        pass


MAX_VOISINS = 10


def voisins(faits, numero):
    total = len(faits)
    if total <= MAX_VOISINS:
        debut, fin = 0, total
    else:
        debut = max(0, min(numero - 5, total - MAX_VOISINS))
        fin = debut + MAX_VOISINS
    lignes = ["", "Faits voisins, calculés par le code (à lire avant de conclure) :"]
    for i in range(debut, fin):
        f = faits[i]
        marque = "->" if i == numero - 1 else "  "
        lignes.append("%s %s = %s" % (marque, f["quoi"], f["valeur"]))
    if total > fin - debut:
        lignes.append("(%d faits au total pour cette recette, %d affichés)" % (total, fin - debut))
    return "\n".join(lignes)


def repondre(question):
    plan = demander_ia(prompt_recette(question))
    if not plan:
        noter(question, "-", "-", "pas de réponse exploitable de l'IA")
        return "L'IA n'a pas répondu de façon exploitable."
    recette = plan.get("recette")
    if recette == "aucune" or recette not in RECETTES:
        noter(question, str(recette), "-", "aucune recette ne convient")
        return "Aucune recette du menu ne répond à cette question."
    param = (plan.get("ip") or "").strip() or None
    print("Recette choisie :", recette, ("| ip : " + param) if param else "")

    res = executer(recette, PCAP, param)
    print("Commande exécutée :", res["cmd"])
    if res["erreur"]:
        noter(question, recette, "-", "erreur tshark")
        return "ERREUR tshark (ce n'est pas une absence de résultat) : " + res["erreur"]
    if not res["faits"]:
        noter(question, recette, "-", "aucun fait")
        return "Aucun fait trouvé dans ce fichier pour cette recette."
    if len(res["faits"]) > MAX_FAITS:
        print("(%d faits trouvés, seuls les %d premiers sont montrés à l'IA)"
              % (len(res["faits"]), MAX_FAITS))

    rep = demander_ia(prompt_fait(question, res["faits"]))
    if not rep:
        noter(question, recette, "-", "pas de fiche exploitable")
        return "L'IA n'a pas produit de fiche exploitable."
    try:
        numero = int(rep.get("numero", 0))
    except (TypeError, ValueError):
        numero = -1
    if numero == 0:
        noter(question, recette, "-", "aucune fiche ne répond")
        return "Aucun fait calculé ne répond à cette question."
    montres = res["faits"][:MAX_FAITS]
    if not 1 <= numero <= len(montres):
        noter(question, recette, "-", "NON PROUVÉE : numéro de fait invalide")
        return "NON PROUVÉE : l'IA a donné un numéro de fait qui n'existe pas."
    choisi = montres[numero - 1]
    quoi, valeur, frames = choisi["quoi"], choisi["valeur"], choisi["frames"]
    print("Fait choisi par l'IA : n°%d, %s = %s | paquets : %s" % (numero, quoi, valeur, frames))
    fiche = "%s = %s" % (quoi, valeur)

    verdict = verifier(PCAP, recette, param,
                       {"quoi": quoi, "valeur": valeur, "frames": frames,
                        "phrase": "%s : %s" % (quoi, valeur)})
    noter(question, recette, fiche, verdict)
    if verdict.startswith("PROUVÉE"):
        texte = "%s\nRÉPONSE (écrite par le code) : %s" % (verdict, phrase_finale(quoi, valeur, frames))
        return texte + voisins(res["faits"], numero)
    return verdict


if __name__ == "__main__":
    print("Fichier analysé :", PCAP)
    if not os.path.exists(PCAP) or os.path.getsize(PCAP) == 0:
        sys.exit("Fichier introuvable ou vide : " + PCAP)
    test = run_tshark(PCAP, "", [], limit=1)
    if test["erreur"] or not test["output"]:
        sys.exit("Fichier illisible ou sans paquet : " + (test["erreur"] or PCAP))
    while True:
        q = input("\nTa question (ou 'q' pour quitter) : ").strip()
        if q.lower() == "q":
            break
        if q:
            print("VERDICT :", repondre(q))

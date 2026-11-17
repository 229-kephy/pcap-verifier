import os
import re

from outil import executer


def _norm(t):
    return " ".join(str(t).lower().split())


def _contient(phrase, valeur):
    valeur = valeur.rstrip("/") or valeur
    motif = r"(?<![\w.\-])" + re.escape(valeur) + r"(?![\w])"
    return re.search(motif, phrase) is not None


def verifier(pcap, recette, param, affirmation):
    res = executer(recette, pcap, param)
    if res["erreur"]:
        return "NON PROUVÉE : erreur tshark : " + res["erreur"]
    quoi = _norm(affirmation.get("quoi", ""))
    valeur = _norm(affirmation.get("valeur", ""))
    trouve = None
    for f in res["faits"]:
        if _norm(f["quoi"]) == quoi and _norm(f["valeur"]) == valeur:
            trouve = f
            break
    if trouve is None:
        return "NON PROUVÉE : aucun fait « %s = %s » dans le fichier" % (quoi, valeur)
    if not _contient(_norm(affirmation.get("phrase", "")), valeur):
        return "NON PROUVÉE : la phrase ne contient pas la valeur prouvée"
    frames = affirmation.get("frames") or []
    if trouve["frames"]:
        if not frames:
            return "NON PROUVÉE : aucun numéro de paquet cité"
        faux = [x for x in frames if x not in trouve["frames"]]
        if faux:
            return "NON PROUVÉE : les paquets %s ne soutiennent pas ce fait" % faux
    elif frames:
        return "NON PROUVÉE : paquets cités %s alors que ce fait n'en a pas (inventés)" % frames
    return "PROUVÉE"


if __name__ == "__main__":
    P1 = os.path.expanduser("~/mon_test.pcap")
    P2 = os.path.expanduser("~/scan_test4.pcap")
    VM = "192.168.205.131"
    SC = "de 192.168.163.128 vers 192.168.163.1"

    def a(quoi, valeur, phrase, frames=None):
        return {"quoi": quoi, "valeur": valeur, "phrase": phrase, "frames": frames or []}

    tests = [
        ("vrai  : 28 paquets au total", P1, "compteurs", None, a("total de paquets dans le fichier", "28", "Le fichier contient 28 paquets."), True),
        ("faux  : paquets inventés pour un compteur", P1, "compteurs", None, a("total de paquets dans le fichier", "28", "Le fichier contient 28 paquets.", [5, 6, 1]), False),
        ("faux  : 26 pris pour le total", P1, "compteurs", None, a("total de paquets dans le fichier", "26", "Le fichier contient 26 paquets."), False),
        ("vrai  : la VM a envoyé 15", P1, "compteurs", None, a("paquets envoyés par " + VM, "15", "La VM a envoyé 15 paquets."), True),
        ("faux  : envoyés confondus avec reçus", P1, "compteurs", None, a("paquets envoyés par " + VM, "11", "La VM a envoyé 11 paquets."), False),
        ("vrai  : example.com demandé (paquets 1, 5)", P1, "domaines", None, a("domaine demandé", "example.com", "example.com a été demandé.", [1, 5]), True),
        ("faux  : le paquet 4 est une réponse", P1, "domaines", None, a("domaine demandé", "example.com", "example.com a été demandé.", [1, 4]), False),
        ("faux  : orthographe « exemple.com »", P1, "domaines", None, a("domaine demandé", "example.com", "exemple.com a été demandé.", [1]), False),
        ("vrai  : page web au paquet 15", P1, "sites_web", None, a("site web demandé", "example.com/", "La page example.com/ a été demandée.", [15]), True),
        ("vrai  : 200 paquets de sondage", P2, "scan", None, a("paquets de sondage SYN " + SC, "200", "Il y a eu 200 paquets de sondage."), True),
        ("vrai  : 100 ports distincts", P2, "scan", None, a("ports distincts sondés " + SC, "100", "100 ports distincts ont été sondés."), True),
        ("faux  : 200 ports distincts", P2, "scan", None, a("ports distincts sondés " + SC, "200", "200 ports distincts ont été sondés."), False),
    ]
    for nom, pcap, recette, param, aff, attendu in tests:
        verdict = verifier(pcap, recette, param, aff)
        ok = verdict.startswith("PROUVÉE") == attendu
        print("%-7s %-45s -> %s" % ("OK" if ok else "ÉCHEC", nom, verdict))

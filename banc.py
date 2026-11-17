import contextlib
import io
import os
import sys
import time
import urllib.request

REPETITIONS = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 1
sys.argv = sys.argv[:1]

import agent

DOSSIER = os.path.expanduser("~")
RESULTATS = os.path.join(DOSSIER, "resultats_banc.txt")
REFUS = ("aucune recette ne convient", "aucune fiche ne répond")

TESTS = [
    ("mon_test.pcap", "ou suis allé", "site web demandé", "example.com/"),
    ("mon_test.pcap", "Quels noms de domaine ont été demandés ?", "domaine demandé", "example.com"),
    ("mon_test.pcap", "Combien de paquets y a-t-il au total ?", "total de paquets dans le fichier", "28"),
    ("mon_test.pcap", "Combien de paquets 192.168.205.131 a-t-elle émis ?", "paquets envoyés par 192.168.205.131", "15"),
    ("transfert_local.pcap", "Quel document a été récupéré depuis le serveur ?", "fichier demandé par GET", "/rapport.txt"),
    ("transfert_local.pcap", "Quelle est la taille du fichier téléchargé ?", "taille annoncée en octets de /rapport.txt", "27"),
    ("scan_test4.pcap", "Une machine a-t-elle sondé les ports d'une autre ?", "scan de ports probable", "oui"),
    ("scan_test4.pcap", "Combien de ports ont été sondés ?", "ports distincts sondés", "100"),
    ("mon_test.pcap", "Que peux-tu faire comme activité ?", None, None),
]

trace = {}


def noter_capture(question, recette, fiche, verdict):
    trace["recette"] = recette
    trace["fiche"] = fiche
    trace["verdict"] = verdict
    try:
        with open(os.path.join(DOSSIER, "journal_banc.txt"), "a", encoding="utf-8") as f:
            f.write("%s | %s | %s | %s | %s\n" % (os.path.basename(agent.PCAP), question, recette, fiche, verdict))
    except OSError:
        pass


agent.noter = noter_capture
agent.JOURNAL = os.path.join(DOSSIER, "journal_banc.txt")


def verifier_prerequis():
    manquants = []
    for nom in sorted({t[0] for t in TESTS}):
        chemin = os.path.join(DOSSIER, nom)
        if not os.path.exists(chemin) or os.path.getsize(chemin) == 0:
            manquants.append(nom)
    if manquants:
        sys.exit("Fichiers manquants ou vides : " + ", ".join(manquants))
    try:
        base = agent.URL.rsplit("/api/", 1)[0]
        urllib.request.urlopen(base, timeout=5).read()
    except Exception as e:
        sys.exit("Ollama ne répond pas (%s). Allume-le sur Windows et relance." % e)


def poser(chemin, question):
    agent.PCAP = chemin
    trace.clear()
    t0 = time.time()
    tampon = io.StringIO()
    try:
        with contextlib.redirect_stdout(tampon):
            agent.repondre(question)
    except Exception as e:
        trace["verdict"] = "ERREUR Python : %s" % e
    duree = time.time() - t0
    return (trace.get("recette", "-"), trace.get("fiche", "-"),
            trace.get("verdict", "(aucune trace)"), duree)


def correspond(fiche, fragment, valeur):
    if " = " not in fiche:
        return False
    quoi, val = fiche.rsplit(" = ", 1)
    return fragment.lower() in quoi.lower() and val.strip() == valeur


def main():
    verifier_prerequis()
    nb_total = REPETITIONS * len(TESTS)
    compteur = 0
    n_rep = n_refus = 0
    prouvees = pertinentes = correctes = refus_ok = 0
    hors_sujet = []
    debut = time.time()
    for tour in range(REPETITIONS):
        for nom, question, fragment, valeur in TESTS:
            compteur += 1
            chemin = os.path.join(DOSSIER, nom)
            recette, fiche, verdict, duree = poser(chemin, question)
            if fragment is None:
                n_refus += 1
                ok = verdict in REFUS
                refus_ok += 1 if ok else 0
                etat = "refus attendu : " + ("OK" if ok else "ÉCHEC (verdict : %s)" % verdict[:50])
            else:
                n_rep += 1
                p = verdict.startswith("PROUVÉE")
                c = correspond(fiche, fragment, valeur)
                prouvees += 1 if p else 0
                pertinentes += 1 if c else 0
                correctes += 1 if (p and c) else 0
                etat = "prouvée : %s | pertinente : %s" % ("oui" if p else "non", "oui" if c else "non")
                if p and not c:
                    hors_sujet.append(question)
            print("[%d/%d] %-52s %s (%.0f s, recette : %s)"
                  % (compteur, nb_total, question[:52], etat, duree, recette), flush=True)

    print()
    print("=" * 64)
    print("RÉSULTATS : %d tour(s), modèle %s" % (REPETITIONS, agent.MODELE))
    if n_rep:
        print("Prouvées                 : %d/%d (%.0f %%)" % (prouvees, n_rep, 100.0 * prouvees / n_rep))
        print("Pertinentes              : %d/%d (%.0f %%)" % (pertinentes, n_rep, 100.0 * pertinentes / n_rep))
        print("Correctes ET prouvées    : %d/%d (%.0f %%)" % (correctes, n_rep, 100.0 * correctes / n_rep))
    if n_refus:
        print("Refus attendu respecté   : %d/%d" % (refus_ok, n_refus))
    if hors_sujet:
        print("Prouvées mais hors sujet :")
        for q in hors_sujet:
            print("  -", q)
    print("Durée totale : %.0f s" % (time.time() - debut))
    ligne = ("%s | modèle %s | %d tour(s) | prouvées %d/%d | pertinentes %d/%d | "
             "correctes et prouvées %d/%d | refus %d/%d\n"
             % (time.strftime("%Y-%m-%d %H:%M"), agent.MODELE, REPETITIONS,
                prouvees, n_rep, pertinentes, n_rep, correctes, n_rep, refus_ok, n_refus))
    with open(RESULTATS, "a", encoding="utf-8") as f:
        f.write(ligne)
    print("Résumé ajouté à", RESULTATS)


if __name__ == "__main__":
    main()

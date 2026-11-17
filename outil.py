import re
import subprocess
from collections import Counter, defaultdict

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def run_tshark(pcap, display_filter="", fields=None, limit=None):
    cmd = ["tshark", "-r", pcap]
    if display_filter:
        cmd += ["-Y", display_filter]
    cmd += ["-T", "fields", "-e", "frame.number"]
    for f in (fields or []):
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    lignes = out.stdout.splitlines()
    if limit:
        lignes = lignes[:limit]
    erreur = ""
    if out.returncode != 0:
        erreur = " ".join(l for l in out.stderr.splitlines()
                          if l.strip() and "libxml" not in l) or "tshark a échoué"
    return {"cmd": " ".join(cmd), "output": lignes, "erreur": erreur}


def lire(pcap, display_filter, champs):
    res = run_tshark(pcap, display_filter, champs)
    n = len(champs) + 1
    lignes = []
    for l in res["output"]:
        p = l.split("\t")
        p += [""] * (n - len(p))
        lignes.append(p[:n])
    return lignes, res["erreur"], res["cmd"]


def premier(valeur):
    return valeur.split(",")[0].strip()


def fait(quoi, valeur, frames=None):
    return {"quoi": quoi, "valeur": str(valeur), "frames": frames or []}


def recette_domaines(pcap, param=None):
    lignes, err, cmd = lire(pcap, "dns.flags.response == 0", ["dns.qry.name"])
    frames = defaultdict(list)
    for fr, nom in lignes:
        if nom:
            frames[nom].append(int(fr))
    faits = [fait("domaine demandé", n, f) for n, f in frames.items()]
    return {"cmd": cmd, "erreur": err, "faits": faits}


def recette_sites_web(pcap, param=None):
    lignes, err, cmd = lire(pcap, "http.request", ["http.host", "http.request.uri"])
    frames = defaultdict(list)
    for fr, host, uri in lignes:
        frames[(host or "(sans hôte)") + uri].append(int(fr))
    faits = [fait("site web demandé", s, f) for s, f in frames.items()]
    return {"cmd": cmd, "erreur": err, "faits": faits}


def recette_conversations(pcap, param=None):
    lignes, err, cmd = lire(pcap, "ip", ["ip.src", "ip.dst"])
    c = Counter()
    for fr, s, d in lignes:
        a, b = sorted([premier(s), premier(d)])
        c[(a, b)] += 1
    faits = [fait("paquets échangés entre %s et %s" % (a, b), n)
             for (a, b), n in c.items()]
    return {"cmd": cmd, "erreur": err, "faits": faits}


def recette_protocoles(pcap, param=None):
    lignes, err, cmd = lire(pcap, "", ["frame.protocols"])
    c = Counter()
    for fr, proto in lignes:
        for p in set(proto.split(":")):
            if p:
                c[p] += 1
    faits = [fait("paquets contenant le protocole " + p, n) for p, n in c.items()]
    return {"cmd": cmd, "erreur": err, "faits": faits}


def recette_ip(pcap, param=None):
    if not param or not IP_RE.match(param):
        return {"cmd": "", "erreur": "adresse IP manquante ou invalide", "faits": []}
    lignes, err, cmd = lire(pcap, "ip.addr == " + param, ["ip.src", "ip.dst"])
    envoyes = recus = 0
    correspondants = defaultdict(list)
    for fr, s, d in lignes:
        s, d = premier(s), premier(d)
        if s == param:
            envoyes += 1
        if d == param:
            recus += 1
        autre = d if s == param else s
        correspondants[autre].append(int(fr))
    faits = [fait("paquets impliquant " + param, len(lignes)),
             fait("paquets envoyés par " + param, envoyes),
             fait("paquets reçus par " + param, recus)]
    for autre, frames in correspondants.items():
        faits.append(fait("correspondant de " + param, autre, frames[:200]))
    return {"cmd": cmd, "erreur": err, "faits": faits}


def recette_compteurs(pcap, param=None):
    lignes, err, cmd = lire(pcap, "", ["ip.src", "ip.dst"])
    emis, recus = Counter(), Counter()
    nb_ip = 0
    for fr, s, d in lignes:
        s, d = premier(s), premier(d)
        if s:
            nb_ip += 1
            emis[s] += 1
            if d:
                recus[d] += 1
    faits = [fait("total de paquets dans le fichier", len(lignes)),
             fait("total de paquets IPv4", nb_ip)]
    for ip in sorted(set(emis) | set(recus)):
        faits.append(fait("paquets envoyés par " + ip, emis[ip]))
        faits.append(fait("paquets reçus par " + ip, recus[ip]))
    return {"cmd": cmd, "erreur": err, "faits": faits}


def recette_scan(pcap, param=None, seuil=15):
    lignes, err, cmd = lire(pcap, "tcp.flags.syn==1 && tcp.flags.ack==0",
                            ["ip.src", "ip.dst", "tcp.dstport"])
    paquets = Counter()
    ports = defaultdict(set)
    for fr, s, d, p in lignes:
        cle = (premier(s), premier(d))
        paquets[cle] += 1
        ports[cle].add(p)
    faits = []
    for (s, d), n in paquets.items():
        nb = len(ports[(s, d)])
        faits.append(fait("paquets de sondage SYN de %s vers %s" % (s, d), n))
        faits.append(fait("ports distincts sondés de %s vers %s" % (s, d), nb))
        faits.append(fait("scan de ports probable de %s vers %s (au moins %d ports distincts)"
                          % (s, d, seuil), "oui" if nb >= seuil else "non"))
    if not faits:
        faits.append(fait("paquets de sondage SYN", 0))
    return {"cmd": cmd, "erreur": err, "faits": faits}


def recette_fichiers(pcap, param=None):
    lignes, err, cmd = lire(pcap, "http.request or http.response",
                            ["http.request.method", "http.request.uri",
                             "http.response.code", "http.content_length"])
    demandes = defaultdict(list)
    codes = defaultdict(list)
    tailles = defaultdict(list)
    nb_requetes = 0
    for fr, methode, uri, code, taille in lignes:
        if methode:
            nb_requetes += 1
            demandes[(methode, uri)].append(int(fr))
        elif code:
            codes[(uri, code)].append(int(fr))
            if taille:
                tailles[(uri, premier(taille))].append(int(fr))
    faits = [fait("requêtes HTTP envoyées", nb_requetes),
             fait("fichiers distincts demandés", len({u for (m, u) in demandes}))]
    for (methode, uri), frames in demandes.items():
        faits.append(fait("fichier demandé par " + methode, uri, frames))
    for (uri, code), frames in codes.items():
        faits.append(fait("code de réponse pour " + uri, code, frames))
    for (uri, taille), frames in tailles.items():
        faits.append(fait("taille annoncée en octets de " + uri, taille, frames))
    return {"cmd": cmd, "erreur": err, "faits": faits}


RECETTES = {
    "domaines": recette_domaines,
    "sites_web": recette_sites_web,
    "conversations": recette_conversations,
    "protocoles": recette_protocoles,
    "ip": recette_ip,
    "compteurs": recette_compteurs,
    "scan": recette_scan,
    "fichiers": recette_fichiers,
}


def executer(nom, pcap, param=None):
    if nom not in RECETTES:
        return {"cmd": "", "erreur": "recette inconnue : %s" % nom, "faits": []}
    return RECETTES[nom](pcap, param)

# Configuration Zeek du capteur Auspex.

# Logs en JSON : un enregistrement par ligne, lisible directement par Auspex.
@load policy/tuning/json-logs

# Adresses MAC des deux extrémités dans conn.log (orig_l2_addr, resp_l2_addr) :
# indispensable pour identifier le fabricant d'un automate.
@load policy/protocols/conn/mac-logging

# Paquets installés par zkg (parsers ICSNPP).
@load packages

# Les ports SPAN et les cartes réseau qui délèguent le calcul des sommes de
# contrôle produisent souvent des sommes fausses : ne pas jeter ces paquets.
redef ignore_checksums = T;

# Sujet et émetteur du certificat du serveur dans ssl.log : les équipements
# industriels présentent souvent le certificat par défaut de leur constructeur
# (Moxa, Hirschmann, RUGGEDCOM, Digi… relevés sur captures réelles).
@ifdef ( SSL::log_include_server_certificate_subject_issuer )
redef SSL::log_include_server_certificate_subject_issuer = T;
@endif

# En-tête « Server » des réponses HTTP dans http.log (champ server) : serveurs web
# embarqués des automates, IHM et passerelles.
redef record HTTP::Info += {
    server: string &log &optional;
};

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string) &priority=3
    {
    if ( ! is_orig && name == "SERVER" && c?$http )
        c$http$server = value[:200];
    }

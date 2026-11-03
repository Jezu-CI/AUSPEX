# Réglages propres à l'écoute en continu.

@load ./auspex.zeek

# Rotation horaire : Auspex lit les fichiers terminés, le capteur ne garde
# rien de durable (voir la purge dans entrypoint.sh).
redef Log::default_rotation_interval = 1 hr;

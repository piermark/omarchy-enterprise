# Installazione e verifica

Il sistema di riferimento per la qualificazione è Omarchy 4.5 (4.5 o
4.5.0, basato su Arch Linux) su x86_64. Per la prova offline servono Bash e Python. Per
l'interfaccia grafica servono PyGObject, GTK 4.8 o superiore e Libadwaita
1.4 o superiore.

Il pacchetto Arch `omarchy-enterprise-0.5.0-1-any.pkg.tar.zst` (versione
Pacman `0.5.0-1`) richiede firma del maintainer e collaudo su un'installazione
pulita di Omarchy prima della distribuzione. Quando un pacchetto firmato è
disponibile, ottenere l'impronta della chiave da un canale fidato separato
e verificare sia la firma sia gli hash. Seguire la
[procedura completa in inglese](../installation.md).
Mantenere un account amministrativo locale e un backup verificato.

## Pacchetto precompilato

Il pacchetto `omarchy-enterprise-0.5.0-1-any.pkg.tar.zst` sarà pubblicato nelle
Release solo dopo la firma e il collaudo su Omarchy pulito; per ora la release
`v0.5.0` contiene solo i sorgenti. Impronta della chiave di firma (Ed25519,
Marco Porro (Omarchy Enterprise)): `CDBB 05E0 13F4 F1E8 BBE8  F000 6E3D 9649 B45A DEC7`. Dopo averla verificata da un canale
indipendente:

```sh
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
sudo pacman-key --add omarchy-enterprise-signing-key.asc
sudo pacman-key --lsign-key CDBB05E013F4F1E8BBE8F0006E3D9649B45ADEC7
sudo pacman -U omarchy-enterprise-0.5.0-1-any.pkg.tar.zst
```

Avviare **Omarchy Enterprise** dal menu come utente del desktop. Per rimuoverlo:
`sudo pacman -Rns omarchy-enterprise`. Per compilarlo dai sorgenti:
`cd packaging && makepkg --syncdeps`.

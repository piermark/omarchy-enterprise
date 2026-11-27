# Guida rapida

Usare un ambiente di prova sacrificabile e un account senza privilegi
amministrativi. Dopo aver ottenuto e decompresso l'archivio sorgente di
`v0.5.0`, eseguire dalla directory estratta:

```sh
sha256sum -c SOURCE-SHA256SUMS
stage=$(mktemp -d)
./install.sh --root "$stage" --profile standalone --dry-run
```

Il profilo Standalone consente di esaminare le modifiche previste in una
directory privata senza iscrivere il computer al dominio o avviare servizi.
Consultare [l'installazione](installation.md) e la
[guida rapida in inglese](../quick-start.md).

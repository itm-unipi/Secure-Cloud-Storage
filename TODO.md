# To Do List

* dividere il main
* vedere se gli errori del logout sono numerati correttamente
* valutare se mettere il controllo del command_code, command_code sbagliato non puo avvenire se non a causa di un reply attack, in generale se ne accorgerebbe l'errore del counter ma tale errore verrebbe scoperto solo dopo
la deserializzazione del pacchetto che potrebbe fallire se il command_code è diverso
* upper cammel usato in tutti i pacchetti
* sanitizzare path con ..
* uniformare gli output
* decidere se fare una cartella download in locale
* rivedere la gestione del ctrl + c nel server e nel client che va all'infinito
* cancellare print commentate
* Sistemare lo script di test
# To Do List

* creare il .h per le define e il .h per gli error code
* gestire la size a 4G = 0 in download e upload
* cancellare print commentate
* Sistemare lo script di test
* Racchiudere #pragma in una utility function
* vedere se gli errori del logout sono numerati correttamente
* valutare se mettere il controllo del command_code, command_code sbagliato non puo avvenire se non a causa di un reply attack, in generale se ne accorgerebbe l'errore del counter ma tale errore verrebbe scoperto solo dopo
la deserializzazione del pacchetto che potrebbe fallire se il command_code è diverso
* se nel logout si invia sempre il REQ_SUCCESS, che senso ha dato che il TCP ha l'ack automatico?
* upper cammel usato in tutti i pacchetti
* sanitizzare path con ..
* decidere se fare una cartella download in locale
* rivedere la gestione del ctrl + c nel server e nel client che va all'infinito
* dividere il main
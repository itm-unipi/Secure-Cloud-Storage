# To Do List

* Biagio->Download, Matteo->Upload, Gianluca->Rename-List-Delete
* controllare la funzione che incrementa il counter e gestisce l'overflow
* come gestiamo il controllo del counter? (GOTO)
* il filename non può avere il carattere '|', perché è usato come divisore
* cancellare print commentate
* Sistemare lo script di test

## Gianluca

* vedere se gli errori del logout sono numerati correttamente
* valutare se mettere il controllo del command_code, command_code sbagliato non puo avvenire se non a causa di un reply attack, in generale se ne accorgerebbe l'errore del counter ma tale errore verrebbe scoperto solo dopo
la deserializzazione del pacchetto che potrebbe fallire se il command_code è diverso
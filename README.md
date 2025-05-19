# SDES Encryption

O arquivo `sdes.c` implementa e testa o algoritmo S-DES, o executável gerado testa mostra 
o resultado gerado ao rodar o algoritmo em um único byte e posteriormente como ele se 
comporta ao usarmos os modos de operação ECB e CBC.

---
## Compilando o código

Para compilar o código do projeto basta rodar o comando `g++ -std=c++11 sdes.cpp -o sdes`. 
Feito isso basta rodar o executável `sdes` que foi gerado.

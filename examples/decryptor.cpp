#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

int main() {
   int ret; // used for return values
   unsigned char *key = (unsigned char *)"0123456789012345";

   // read the file to decrypt from keyboard:
   string cphr_file_name;
   cout << "Please, type the file to decrypt: ";
   getline(cin, cphr_file_name);
   if(!cin) { cerr << "Error during input\n"; exit(1); }

   // open the file to decrypt:
   FILE* cphr_file = fopen(cphr_file_name.c_str(), "rb");
   if(!cphr_file) { cerr << "Error: cannot open file '" << cphr_file_name << "' (file does not exist?)\n"; exit(1); }

   // get the file size: 
   // (assuming no failures in fseek() and ftell())
   fseek(cphr_file, 0, SEEK_END);
   long int cphr_file_size = ftell(cphr_file);
   fseek(cphr_file, 0, SEEK_SET);

   // declare some useful variables:
   const EVP_CIPHER* cipher = EVP_aes_128_cbc();
   int iv_len = EVP_CIPHER_iv_length(cipher);
   
   // Allocate buffer for IV, ciphertext, plaintext
   unsigned char* iv = (unsigned char*)malloc(iv_len);
   int cphr_size = cphr_file_size - iv_len;
   unsigned char* cphr_buf = (unsigned char*)malloc(cphr_size);
   unsigned char* clear_buf = (unsigned char*)malloc(cphr_size);
   if(!iv || !cphr_buf || !clear_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }

   // read the IV and the ciphertext from file:
   ret = fread(iv, 1, iv_len, cphr_file);
   if(ret < iv_len) { cerr << "Error while reading file '" << cphr_file_name << "'\n"; exit(1); }
   ret = fread(cphr_buf, 1, cphr_size, cphr_file);
   if(ret < cphr_size) { cerr << "Error while reading file '" << cphr_file_name << "'\n"; exit(1); }
   fclose(cphr_file);

   //Create and initialise the context
   EVP_CIPHER_CTX *ctx;
   ctx = EVP_CIPHER_CTX_new();
   if(!ctx){ cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; exit(1); }
   ret = EVP_DecryptInit(ctx, cipher, key, iv);
   if(ret != 1){
      cerr <<"Error: DecryptInit Failed\n";
      exit(1);
   }
   
   int update_len = 0; // bytes decrypted at each chunk
   int total_len = 0; // total decrypted bytes
   
   // Decrypt Update: one call is enough because our ciphertext is small.
   ret = EVP_DecryptUpdate(ctx, clear_buf, &update_len, cphr_buf, cphr_size);
   if(ret != 1){
      cerr <<"Error: DecryptUpdate Failed\n";
      exit(1);
   }
   total_len += update_len;
   
   //Decrypt Final. Finalize the Decryption and adds the padding
   ret = EVP_DecryptFinal(ctx, clear_buf + total_len, &update_len);

   if(ret != 1){
      cerr <<"Error: DecryptFinal Failed\n";
      exit(1);
   }
   total_len += update_len;
   int clear_size = total_len;

   // delete the context from memory:
   EVP_CIPHER_CTX_free(ctx);
   

   // write the plaintext into a '.dec' file:
   string clear_file_name = cphr_file_name + ".dec";
   FILE* clear_file = fopen(clear_file_name.c_str(), "wb");
   if(!clear_file) { cerr << "Error: cannot open file '" << clear_file_name << "' (no permissions?)\n"; exit(1); }
   ret = fwrite(clear_buf, 1, clear_size, clear_file);
   if(ret < clear_size) { cerr << "Error while writing the file '" << clear_file_name << "'\n"; exit(1); }
   fclose(clear_file);
   
   // Just out of curiosity, print on stdout the used IV retrieved from file.
   cout<<"Used IV:"<<endl;
   BIO_dump_fp (stdout, (const char *)iv, iv_len);
   
   // delete the plaintext from memory:
   // Telling the compiler it MUST NOT optimize the following instruction. 
   // With optimization the memset would be skipped, because of the next free instruction.
#pragma optimize("", off)
   memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
   free(clear_buf);

   cout << "File '"<< cphr_file_name << "' decrypted into file '" << clear_file_name << "', clear size is " << clear_size << " bytes\n";

   // deallocate buffers:
   free(iv);
   free(cphr_buf);

   return 0;
}

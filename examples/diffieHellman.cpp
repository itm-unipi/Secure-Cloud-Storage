#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>


using namespace std;

static DH *get_dh2048_auto(void)
{
    static unsigned char dhp_2048[] = {
        0xF9, 0xEA, 0x2A, 0x73, 0x80, 0x26, 0x19, 0xE4, 0x9F, 0x4B,
        0x88, 0xCB, 0xBF, 0x49, 0x08, 0x60, 0xC5, 0xBE, 0x41, 0x42,
        0x59, 0xDB, 0xEC, 0xCA, 0x1A, 0xC9, 0x90, 0x9E, 0xCC, 0xF8,
        0x6A, 0x3B, 0x60, 0x5C, 0x14, 0x86, 0x19, 0x09, 0x36, 0x29,
        0x39, 0x36, 0x21, 0xF7, 0x55, 0x06, 0x1D, 0xA3, 0xED, 0x6A,
        0x16, 0xAB, 0xAA, 0x18, 0x2B, 0x29, 0xE9, 0x64, 0x48, 0x67,
        0x88, 0xB4, 0x80, 0x46, 0xFD, 0xBF, 0x47, 0x17, 0x91, 0x4A,
        0x9C, 0x06, 0x0A, 0x58, 0x23, 0x2B, 0x6D, 0xF9, 0xDD, 0x1D,
        0x93, 0x95, 0x8F, 0x76, 0x70, 0xC1, 0x80, 0x10, 0x4B, 0x3D,
        0xAC, 0x08, 0x33, 0x7D, 0xDE, 0x38, 0xAB, 0x48, 0x7F, 0x38,
        0xC4, 0xA6, 0xD3, 0x96, 0x4B, 0x5F, 0xF9, 0x4A, 0xD7, 0x4D,
        0xAE, 0x10, 0x2A, 0xD9, 0xD3, 0x4A, 0xF0, 0x85, 0x68, 0x6B,
        0xDE, 0x23, 0x9A, 0x64, 0x02, 0x2C, 0x3D, 0xBC, 0x2F, 0x09,
        0xB3, 0x9E, 0xF1, 0x39, 0xF6, 0xA0, 0x4D, 0x79, 0xCA, 0xBB,
        0x41, 0x81, 0x02, 0xDD, 0x30, 0x36, 0xE5, 0x3C, 0xB8, 0x64,
        0xEE, 0x46, 0x46, 0x5C, 0x87, 0x13, 0x89, 0x85, 0x7D, 0x98,
        0x0F, 0x3C, 0x62, 0x93, 0x83, 0xA0, 0x2F, 0x03, 0xA7, 0x07,
        0xF8, 0xD1, 0x2B, 0x12, 0x8A, 0xBF, 0xE3, 0x08, 0x12, 0x5F,
        0xF8, 0xAE, 0xF8, 0xCA, 0x0D, 0x52, 0xBC, 0x37, 0x97, 0xF0,
        0xF5, 0xA7, 0xC3, 0xBB, 0xC0, 0xE0, 0x54, 0x7E, 0x99, 0x6A,
        0x75, 0x69, 0x17, 0x2D, 0x89, 0x1E, 0x64, 0xE5, 0xB6, 0x99,
        0xCE, 0x84, 0x08, 0x1D, 0x89, 0xFE, 0xBC, 0x80, 0x1D, 0xA1,
        0x14, 0x1C, 0x66, 0x22, 0xDA, 0x35, 0x1D, 0x6D, 0x53, 0x98,
        0xA8, 0xDD, 0xD7, 0x5D, 0x99, 0x13, 0x19, 0x3F, 0x58, 0x8C,
        0x4F, 0x56, 0x5B, 0x16, 0xE8, 0x59, 0x79, 0x81, 0x90, 0x7D,
        0x7C, 0x75, 0x55, 0xB8, 0x50, 0x63
    };
    static unsigned char dhg_2048[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}

int handleErrors(){
	printf("An error occourred.\n");
	exit(1);
}
		
int main() {

    // ---------------------- SETUP DH PARAMETERS ----------------------

    /* Use built-in parameters */
    printf("Start: loading standard DH parameters\n");

    EVP_PKEY *params;
    if(NULL == (params = EVP_PKEY_new())) 
        handleErrors();

    DH* temp = get_dh2048_auto();
    if(1 != EVP_PKEY_set1_DH(params, temp)) 
        handleErrors();

    DH_free(temp);
    printf("\n");
    printf("Generating ephemeral DH KeyPair\n");

    // ---------------- PEER 1 EPHEMERAL KEY GENERATION ----------------

    /* Create context for the key generation */
    EVP_PKEY_CTX *DHctx;
    if(!(DHctx = EVP_PKEY_CTX_new(params, NULL))) 
        handleErrors();

    /* Generate a new key */
    EVP_PKEY *my_dhkey = NULL;
    if(1 != EVP_PKEY_keygen_init(DHctx)) 
        handleErrors();
    if(1 != EVP_PKEY_keygen(DHctx, &my_dhkey)) 
        handleErrors();

    /*write my public key into a file, so the other client can read it*/
    string my_pubkey_file_name = "bin/peer1.pem";
    FILE* p1w = fopen(my_pubkey_file_name.c_str(), "w");
    if (!p1w) { 
        cerr << "Error: cannot open file '"<< my_pubkey_file_name << "' (missing?)" << endl; 
        exit(1); 
    }
    PEM_write_PUBKEY(p1w, my_dhkey);
    fclose(p1w);

    // ---------------- PEER 2 EPHEMERAL KEY GENERATION ----------------
    
    /* Create context for the key generation */
    EVP_PKEY_CTX *DHctx2;
    if(!(DHctx2 = EVP_PKEY_CTX_new(params, NULL))) 
        handleErrors();

    /* Generate a new key */
    EVP_PKEY *my_dhkey2 = NULL;
    if(1 != EVP_PKEY_keygen_init(DHctx2)) 
        handleErrors();
    if(1 != EVP_PKEY_keygen(DHctx2, &my_dhkey2)) 
        handleErrors();

    /*write my public key into a file, so the other client can read it*/
    string my_pubkey_file_name2 = "bin/peer2.pem";
    FILE* p2w = fopen(my_pubkey_file_name2.c_str(), "w");
    if (!p2w) { 
        cerr << "Error: cannot open file '"<< my_pubkey_file_name2 << "' (missing?)" << endl; 
        exit(1); 
    }
    PEM_write_PUBKEY(p2w, my_dhkey2);
    fclose(p2w);

    // ----------------- PEER 2 EPHEMERAL KEY LOADING ------------------

    /*Load peer public key from a file*/
    string peer_pubkey_file_name = "bin/peer2.pem";
    FILE* p2r = fopen(peer_pubkey_file_name.c_str(), "r");
    if (!p2r) { 
        cerr << "Error: cannot open file '"<< peer_pubkey_file_name << "' (missing?)" << endl; 
        exit(1); 
    }

    EVP_PKEY* peer_pubkey = PEM_read_PUBKEY(p2r, NULL, NULL, NULL);
    fclose(p2r);

    if (!peer_pubkey) { 
        cerr << "Error: PEM_read_PUBKEY returned NULL" << endl; 
        exit(1); 
    }

    // -------------------- SHARED KEY GENERATION ----------------------

    printf("Deriving a shared secret\n");

    /*creating a context, the buffer for the shared key and an int for its length*/
    EVP_PKEY_CTX *derive_ctx;
    unsigned char *skey;
    size_t skeylen;
    derive_ctx = EVP_PKEY_CTX_new(my_dhkey,NULL);
    if (!derive_ctx) 
        handleErrors();
    if (EVP_PKEY_derive_init(derive_ctx) <= 0) 
        handleErrors();

    /*Setting the peer with its pubkey*/
    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pubkey) <= 0) 
        handleErrors();

    /* Determine buffer length, by performing a derivation but writing the result nowhere */
    EVP_PKEY_derive(derive_ctx, NULL, &skeylen);

    /*allocate buffer for the shared secret*/
    skey = (unsigned char*)(malloc(int(skeylen)));
    if (!skey) 
        handleErrors();
        
    /*Perform again the derivation and store it in skey buffer*/
    if (EVP_PKEY_derive(derive_ctx, skey, &skeylen) <= 0) 
        handleErrors();

    printf("Here it is the shared secret: \n");
    BIO_dump_fp (stdout, (const char *)skey, skeylen);

    /*WARNING! YOU SHOULD NOT USE THE DERIVED SECRET AS A SESSION KEY!
    * IS COMMON PRACTICE TO HASH THE DERIVED SHARED SECRET TO OBTAIN A SESSION KEY.
    */

    // -----------------------------------------------------------------
    
    //FREE EVERYTHING INVOLVED WITH THE EXCHANGE (not the shared secret tho)
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(peer_pubkey);
    EVP_PKEY_free(my_dhkey);
    EVP_PKEY_CTX_free(DHctx);
    EVP_PKEY_free(params);

    return 0;
}

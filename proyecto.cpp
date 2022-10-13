#include <iostream>
#include <iomanip>
#include "sodium.h"
//Para la tarea
#include <iostream>
#include <fstream>
#include <cstring>

//libraries related to signatures
#include <CkRsa.h>
#include <CkBinData.h>

//libraries to signing files
#include <CkPrivateKey.h>

//libraries to verify signature
#include <CkGlobal.h>
#include <CkPublicKey.h>

#include <CkGlobal.h>

#include <CkPrivateKey.h>
#include <CkRsa.h>
#include <CkBinData.h>

using namespace std;
#define CHUNK_SIZE 4096
static int
encrypt(const char* target_file, const char* source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_in[CHUNK_SIZE];
    unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE* fp_t, * fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    unsigned char  tag;
    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, fp_t);
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
            NULL, 0, tag);
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);
    fclose(fp_t);
    fclose(fp_s);
    return 0;
}
static int
decrypt(const char* target_file, const char* source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE* fp_t, * fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = -1;
    unsigned char  tag;
    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    fread(header, 1, sizeof header, fp_s);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        goto ret; /* incomplete header */
    }
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
            buf_in, rlen, NULL, 0) != 0) {
            goto ret; /* corrupted chunk */
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            goto ret; /* premature end (end of file reached before the end of the stream) */
        }
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);
    ret = 0;
ret:
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}

void sigFile(void)
{
    string private_key_path = "";
    //D:/Escritorio/testCrip/private_key.pem
    string save_file_path = "";
    //D:/Escritorio/testCrip/firmas
    string org_file_path = "";
    //D:/Escritorio/testCrip/original.txt
    string save_sig_file_name = "";
    //sig_file

    cout << "Ingresa la ruta de tu llave privada:\n";
    cin >> private_key_path;
    cout << "Ingresa la ruta de tu archivo:\n";
    cin >> org_file_path;
    cout << "Ingresa la ruta donde guardar tu archivo:\n";
    cin >> save_file_path;
    cout << "Ingresa el nombre para guardar tu archivo:\n";
    cin >> save_sig_file_name;
    
    CkPrivateKey pkey;

    bool success = pkey.LoadPemFile(private_key_path.c_str());
    if (success != true) {
        std::cout << pkey.lastErrorText() << "\r\n";
        return;
    }

    CkRsa rsa;

    success = rsa.ImportPrivateKeyObj(pkey);
    if (success != true) {
        std::cout << rsa.lastErrorText() << "\r\n";
        return;
    }

    rsa.put_LittleEndian(false);

    // Load the file to be signed.
    CkBinData bdFileData;
    success = bdFileData.LoadFile(org_file_path.c_str());

    CkBinData bdSig;
    success = rsa.SignBd(bdFileData, "sha256", bdSig);
    if (success != true) {
        std::cout << rsa.lastErrorText() << "\r\n";
        return;
    }

    success = bdSig.WriteFile((save_file_path + "/" + save_sig_file_name).c_str());
    if (success != true) {
        std::cout << "Failed to write signature.sig." << "\r\n";
        return;
    }

    std::cout << "Success." << "\r\n";
}

void verifySig(void)
{
    string private_key_path = "";
    //D:/Escritorio/testCrip/private_key.pem
    string save_sig_file_path = "";
    //D:/Escritorio/testCrip/firmas/
    string org_file_path = "";
    //D:/Escritorio/testCrip/original.txt

    cout << "Ingresa la ruta de tu llave privada:\n";
    cin >> private_key_path;
    cout << "Ingresa la ruta de tu archivo:\n";
    cin >> org_file_path;
    cout << "Ingresa la ruta del archivo firmado:\n";
    cin >> save_sig_file_path;

    CkPublicKey pubKey;

    bool success = pubKey.LoadOpenSslPemFile(private_key_path.c_str());
    if (success != true) {
        std::cout << pubKey.lastErrorText() << "\r\n";
        return;
    }

    CkBinData bdFileData;
    success = bdFileData.LoadFile(org_file_path.c_str());

    // Load the signature.
    CkBinData bdSig;
    success = bdSig.LoadFile(save_sig_file_path.c_str());

    CkRsa rsa;

    // Import the public key into the RSA component:
    success = rsa.ImportPublicKeyObj(pubKey);
    if (success != true) {
        std::cout << rsa.lastErrorText() << "\r\n";
        return;
    }

    // OpenSSL uses big-endian.
    rsa.put_LittleEndian(false);

    success = rsa.VerifyBd(bdFileData, "sha256", bdSig);
    if (success != true) {
        std::cout << rsa.lastErrorText() << "\r\n";
        std::cout << "The signature was invalid." << "\r\n";
        return;
    }

    std::cout << "The signature was verified." << "\r\n";
}

int main()
{
    if (sodium_init()<0) {
        return -1;
    }
    string target_file="";
    string save_file_name = "";
    string save_file_path = "";

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    crypto_secretstream_xchacha20poly1305_keygen(key);
    //D:/Escritorio/testCrip/original.txt

    int op = 0;
    
    while (op != -1) {
    
        cout << "ingrese una opcion\n1.-Generación y Recuperación de Claves hacia o desde 1 archivo\n2.-Cifrado de Archivos\n3.-Descifrado de Archivos\n4.-Firma de Archivos\n5.-Verificación de Firma de Archivos\nsalir (-1)";
        cin >> op;

        switch (op)
        {
        case 1:
            cout << "No me salió";
            break;

        case 2:
            cout << "ingrese la ruta del archivo a encriptar:\n";
            cin >> target_file;
            cout << "Ingrese la ruta donde guardar el archivo\n";
            cin >> save_file_path;
            cout << "Ingrese el nombre del archivo para guardar\n";
            cin >> save_file_name;

            if (encrypt((save_file_path + "/" + save_file_name).c_str(), target_file.c_str(), key) != 0) {
                cout << "Ocurrio un error\n";
            }
            else {
                cout << "Su archivo encriptado esta en: "<< (save_file_path + "/" + save_file_name).c_str() <<"\n";
            }
            break;

        case 3:
            cout << "ingrese la ruta del archivo a desencriptar:\n";
            cin >> target_file;
            cout << "Ingrese la ruta donde guardar el archivo\n";
            cin >> save_file_path;
            cout << "Ingrese el nombre del archivo para guardar\n";
            cin >> save_file_name;

            if (decrypt((save_file_path+"/"+save_file_name).c_str(), target_file.c_str(), key) != 0) {
                cout << "Ocurrio un error\n";
            }
            else {
                cout << "Su archivo desencriptado esta en: " << (save_file_path + "/" + save_file_name).c_str() << "\n";
            }
            break;

        case 4:
            sigFile();
            break;

        case 5:
            verifySig();
            break;

        case -1:
            break;
        default:
            cout << "opcion no valida\n";
        }
        cout << "\n";
    }
    
    return 0;
}
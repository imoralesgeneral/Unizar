// Compilar con: cl /EHsc /std:c++17 .\cifrar.cpp Advapi32.lib

#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <locale>
#include <codecvt>
#pragma comment(lib, "advapi32.lib")

using namespace std;

namespace fs = std::filesystem;

#define AES_KEY_SIZE 16
#define IN_CHUNK_SIZE (AES_KEY_SIZE * 10) // a buffer must be a multiple of the key size
#define OUT_CHUNK_SIZE (IN_CHUNK_SIZE * 2) // an output buffer (for encryption) must be twice as big

std::vector<std::string> retrieveTextFiles(const std::string& folderPath) {
    std::vector<std::string> fileNames;
    for (const auto& entry : fs::directory_iterator(folderPath)) {
        if (entry.is_regular_file() && entry.path().extension() == ".txt") {
            fileNames.push_back(entry.path().filename().string());
        }
    }
    return fileNames;
}

std::vector<std::string> retrieveEncodedFiles(const std::string& folderPath) {
    std::vector<std::string> fileNames;
    for (const auto& entry : fs::directory_iterator(folderPath)) {
        if (entry.is_regular_file() && entry.path().extension() == ".enc") {
            fileNames.push_back(entry.path().filename().string());
        }
    }
    return fileNames;
}

// Función para convertir un wchar_t* a std::string
std::string wcharToString(const wchar_t* wstr) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

//params: <path> <is decrypt mode> <key>
int wmain(int argc, wchar_t *argv[])
{

    wchar_t default_path[] = L"C:\\TEST\\";
    wchar_t *path = default_path;

    std::string folderPathStr = wcharToString(path);

    //std::vector<std::string> textFiles;

    wchar_t default_key[] = L"clave";
    wchar_t *key_str = default_key;

    //BOOL isDecrypt = FALSE;
    //std::wstring decrypt = argv[2];
    printf("Encrypt mode\n");

    const size_t len = lstrlenW(key_str);
    const size_t key_size = len * sizeof(key_str[0]); // size in bytes

    printf("Key: %S\n", key_str);
    printf("Key len: %#x\n", len);
    printf("Key size: %#x\n", key_size);
    printf("Input path: %S\n", path);
   // printf("Output File: %S\n", filename2);
    printf("----\n");

    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
    HCRYPTPROV hProv;
    if (!CryptAcquireContextW(&hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %x\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        system("pause");
        return dwStatus;
    }
    HCRYPTHASH hHash;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        dwStatus = GetLastError();
        printf("CryptCreateHash failed: %x\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        system("pause");
        return dwStatus;
    }

    if (!CryptHashData(hHash, (BYTE*)key_str, key_size, 0)) {
        DWORD err = GetLastError();
        printf("CryptHashData Failed : %#x\n", err);
        system("pause");
        return (-1);
    }
    printf("[+] CryptHashData Success\n");

    HCRYPTKEY hKey;
    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
        dwStatus = GetLastError();
        printf("CryptDeriveKey failed: %x\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        system("pause");
        return dwStatus;
    }
    printf("[+] CryptDeriveKey Success\n");

    printf("ENCRYPTING...\n");
    std::vector<std::string> textFiles = retrieveTextFiles(folderPathStr);
    for (const std::string& filename : textFiles) {
        // Convertir el nombre de archivo a std::wstring
        std::wstring wFilename(filename.begin(), filename.end());
        // Pasar el path
        wFilename = path + wFilename;
        // Variable const wchar_t* para el nombre de archivo de entrada
        const wchar_t* input = wFilename.c_str();
        // Crear una copia de wFilename para el nombre de archivo de salida
        std::wstring wOutputFilename = wFilename;
        // Agregar la extensión ".dec" al nombre de archivo de salida
        wOutputFilename += L".enc";
        // Variable const wchar_t* para el nombre de archivo de salida
        const wchar_t* output = wOutputFilename.c_str();
        /*std::wcout << L"Archivo de entrada: " << input << std::endl;
        std::wcout << L"Archivo de salida: " << output << std::endl;*/
        HANDLE hInpFile = CreateFileW(input, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (hInpFile == INVALID_HANDLE_VALUE) {
            printf("Cannot open input file!\n");
            system("pause");
            return (-1);
        }
        HANDLE hOutFile = CreateFileW(output, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOutFile == INVALID_HANDLE_VALUE) {
            printf("Cannot open output file!\n");
            system("pause");
            return (-1);
        }
        const size_t chunk_size = OUT_CHUNK_SIZE;
        BYTE *chunk = new BYTE[chunk_size];
        DWORD out_len = 0;
        BOOL isFinal = FALSE;
        DWORD readTotalSize = 0;
        DWORD inputSize = GetFileSize(hInpFile, NULL);
        while (bResult = ReadFile(hInpFile, chunk, IN_CHUNK_SIZE, &out_len, NULL)) {
            if (0 == out_len) {
                break;
            }
            readTotalSize += out_len;
            if (readTotalSize >= inputSize) {
                isFinal = TRUE;
                //printf("Final chunk set, len: %d = %x\n", out_len, out_len);
            }
            if (!CryptEncrypt(hKey, NULL, isFinal, 0, chunk, &out_len, chunk_size)) {
                printf("[-] CryptEncrypt failed: %x\n", GetLastError());
                break;
            }
            DWORD written = 0;
            if (!WriteFile(hOutFile, chunk, out_len, &written, NULL)) {
                printf("writing failed!\n");
                break;
            }
            memset(chunk, 0, chunk_size);
        }
        delete[]chunk; chunk = NULL;
        CloseHandle(hInpFile);
        CloseHandle(hOutFile);
        Sleep(1000);
    }

    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    return 0;
}

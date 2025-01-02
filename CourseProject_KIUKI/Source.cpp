#include <Windows.h>
#include <AclAPI.h>
#include <iostream>
#include <sddl.h>
#include <set>
#include <bitset>
#include <sstream>

void DecodeReadAccessBits(DWORD mask, std::stringstream& result) {
  if (mask & GENERIC_READ) {
    result << "GENERIC_READ" << std::endl;
  }
  else {
    if (mask & FILE_READ_DATA) result << "FILE_READ_DATA" << std::endl;
    if (mask & FILE_READ_ATTRIBUTES) result << "FILE_READ_ATTRIBUTES" << std::endl;
    if (mask & FILE_READ_EA) result << "FILE_READ_EA" << std::endl;
    if (mask & STANDARD_RIGHTS_READ) result << "STANDARD_RIGHTS_READ" << std::endl;
  }
}

void DecodeWriteAccessBits(DWORD mask, std::stringstream& result) {
  if (mask & GENERIC_WRITE) {
    result << "GENERIC_WRITE" << std::endl;
  }
  else {
    if (mask & FILE_WRITE_DATA) result << "FILE_WRITE_DATA" << std::endl;
    if (mask & FILE_APPEND_DATA) result << "FILE_APPEND_DATA" << std::endl;
    if (mask & FILE_WRITE_ATTRIBUTES) result << "FILE_WRITE_ATTRIBUTES" << std::endl;
    if (mask & FILE_WRITE_EA) result << "FILE_WRITE_EA" << std::endl;
    if (mask & STANDARD_RIGHTS_WRITE) result << "STANDARD_RIGHTS_WRITE" << std::endl;
  }
}

void DecodeExecuteAccessBits(DWORD mask, std::stringstream& result) {
  if (mask & GENERIC_EXECUTE) {
    result << "GENERIC_EXECUTE" << std::endl;
  }
  else {
    if (mask & FILE_EXECUTE) result << "FILE_EXECUTE" << std::endl;
    if (mask & STANDARD_RIGHTS_EXECUTE) result << "STANDARD_RIGHTS_EXECUTE" << std::endl;
  }
}

void DecodeAccessMask(DWORD mask, std::stringstream& result) {
  result << "Mask: " << std::bitset<32>(mask) << std::endl;
  if (mask & GENERIC_ALL) result << "GENERIC_ALL" << std::endl;

  DecodeReadAccessBits(mask, result);
  DecodeWriteAccessBits(mask, result);
  DecodeExecuteAccessBits(mask, result);

  if (mask & DELETE) result << "DELETE" << std::endl;
  if (mask & WRITE_DAC) result << "WRITE_DAC" << std::endl;
  if (mask & WRITE_OWNER) result << "WRITE_OWNER" << std::endl;
  if (mask & SYNCHRONIZE) result << "SYNCHRONIZE" << std::endl;
}

void RetrieveAceInfo(PACE_HEADER pAceHeader, std::set<std::string>& uniqueUsers, std::stringstream& result) {
  ACCESS_ALLOWED_ACE* pAce = (ACCESS_ALLOWED_ACE*)pAceHeader;
  char* accountName = NULL;
  char* domainName = NULL;
  SID_NAME_USE sidType;
  DWORD accountNameSize = 0;
  DWORD domainNameSize = 0;

  LookupAccountSidA(NULL, &pAce->SidStart, NULL, &accountNameSize, NULL, &domainNameSize, &sidType);

  accountName = (char*)malloc(accountNameSize * sizeof(char));
  domainName = (char*)malloc(domainNameSize * sizeof(char));

  if (LookupAccountSidA(NULL, &pAce->SidStart, accountName, &accountNameSize, domainName, &domainNameSize, &sidType)) {
    std::string fullName = (domainName[0] != '\0' ? std::string(domainName) + "\\" : "") + accountName;

    result << "User: " << fullName << std::endl;
    DecodeAccessMask(pAce->Mask, result);
    result << std::endl;
  }

  free(accountName);
  free(domainName);
}

char* RetrieveFileAccessInfo(const char* filePath) {
  static std::stringstream result;
  result.str("");

  PSECURITY_DESCRIPTOR pSD;
  if (GetNamedSecurityInfoA(filePath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pSD) == ERROR_SUCCESS) {
    PACL pDacl;
    BOOL bDaclPresent, bDaclDefaulted;

    if (GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted)) {
      if (bDaclPresent) {
        std::set<std::string> uniqueUsers;
        for (DWORD i = 0; i < pDacl->AceCount; ++i) {
          PACE_HEADER pAceHeader;
          if (GetAce(pDacl, i, (LPVOID*)&pAceHeader)) {
            RetrieveAceInfo(pAceHeader, uniqueUsers, result);
          }
        }
      }
    }
    LocalFree(pSD);
  }
  else {
    result << "Failed to get security information for " << filePath << std::endl;
  }

  size_t size = result.str().size() + 1;
  char* output = new char[size];
  strcpy_s(output, size, result.str().c_str());
  return output;
}

typedef char* (*RetrieveAccessMaskStringFunc)(const char*);

int main() {
  HMODULE hModule = LoadLibrary(L"AccessMaskProcessor.dll");
  if (hModule == NULL) {
    std::wcerr << L"Failed to load DLL!" << std::endl;
    return 1;
  }

  // Получение адреса функции
  RetrieveAccessMaskStringFunc RetrieveAccessMaskString = (RetrieveAccessMaskStringFunc)GetProcAddress(hModule, "RetrieveFileAccessInfo");
  if (RetrieveAccessMaskString == NULL) {
    std::wcerr << L"Failed to find function!" << std::endl;
    FreeLibrary(hModule);
    return 1;
  }


  //const char* filePath1 = "C:/Users/Queue/Downloads/test123.txt";
  const char* filePath1 = "C:/Users/Queue/Downloads/Reterraforged-Mod-Forge-1.20.1.jar";
  char* result1 = RetrieveAccessMaskString(filePath1);
  std::cout << result1 << std::endl;
  delete[] result1;  // Don't forget to free the memory!

  //const char* filePath2 = "C:\\Windows\\System32";
  //char* result2 = GetFileAccessInfo(filePath2);
  //std::cout << result2 << std::endl;
  //delete[] result2;  // Don't forget to free the memory!

  return 0;
}


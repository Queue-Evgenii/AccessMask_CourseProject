#include "pch.h"

void DecodeReadAccessBits(DWORD mask, std::stringstream& result) {
  if (mask & GENERIC_READ) {
    result << "GENERIC_READ" << "\r\n";
  }
  else {
    if (mask & FILE_READ_DATA) result << "FILE_READ_DATA" << "\r\n";
    if (mask & FILE_READ_ATTRIBUTES) result << "FILE_READ_ATTRIBUTES" << "\r\n";
    if (mask & FILE_READ_EA) result << "FILE_READ_EA" << "\r\n";
    if (mask & STANDARD_RIGHTS_READ) result << "STANDARD_RIGHTS_READ" << "\r\n";
  }
}

void DecodeWriteAccessBits(DWORD mask, std::stringstream& result) {
  if (mask & GENERIC_WRITE) {
    result << "GENERIC_WRITE" << "\r\n";
  }
  else {
    if (mask & FILE_WRITE_DATA) result << "FILE_WRITE_DATA" << "\r\n";
    if (mask & FILE_APPEND_DATA) result << "FILE_APPEND_DATA" << "\r\n";
    if (mask & FILE_WRITE_ATTRIBUTES) result << "FILE_WRITE_ATTRIBUTES" << "\r\n";
    if (mask & FILE_WRITE_EA) result << "FILE_WRITE_EA" << "\r\n";
    if (mask & STANDARD_RIGHTS_WRITE) result << "STANDARD_RIGHTS_WRITE" << "\r\n";
  }
}

void DecodeExecuteAccessBits(DWORD mask, std::stringstream& result) {
  if (mask & GENERIC_EXECUTE) {
    result << "GENERIC_EXECUTE" << "\r\n";
  }
  else {
    if (mask & FILE_EXECUTE) result << "FILE_EXECUTE" << "\r\n";
    if (mask & STANDARD_RIGHTS_EXECUTE) result << "STANDARD_RIGHTS_EXECUTE" << "\r\n";
  }
}

void DecodeAccessMask(DWORD mask, std::stringstream& result) {
  result << "Mask: " << std::bitset<32>(mask) << "\r\n";
  if (mask & GENERIC_ALL) result << "GENERIC_ALL" << "\r\n";

  DecodeReadAccessBits(mask, result);
  DecodeWriteAccessBits(mask, result);
  DecodeExecuteAccessBits(mask, result);

  if (mask & DELETE) result << "DELETE" << "\r\n";
  if (mask & WRITE_DAC) result << "WRITE_DAC" << "\r\n";
  if (mask & WRITE_OWNER) result << "WRITE_OWNER" << "\r\n";
  if (mask & SYNCHRONIZE) result << "SYNCHRONIZE" << "\r\n";
}

void RetrieveAceInfo(PACE_HEADER pAceHeader, std::stringstream& result) {
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

    result << "User: " << fullName << "\r\n";
    DecodeAccessMask(pAce->Mask, result);
    result << "\r\n";
  }

  free(accountName);
  free(domainName);
}

extern "C" __declspec(dllexport) char* RetrieveFileAccessInfoByPath(const char* filePath) {
  static std::stringstream result;
  result.str("");

  PSECURITY_DESCRIPTOR pSD;
  if (GetNamedSecurityInfoA(filePath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pSD) == ERROR_SUCCESS) {
    PACL pDacl;
    BOOL bDaclPresent, bDaclDefaulted;

    if (GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted)) {
      if (bDaclPresent) {
        for (DWORD i = 0; i < pDacl->AceCount; ++i) {
          PACE_HEADER pAceHeader;
          if (GetAce(pDacl, i, (LPVOID*)&pAceHeader)) {
            RetrieveAceInfo(pAceHeader, result);
          }
        }
      }
    }
    LocalFree(pSD);
  }
  else {
    result << "Failed to get security information for " << filePath << "\r\n";
  }

  size_t size = result.str().size() + 1;
  char* output = new char[size];
  strcpy_s(output, size, result.str().c_str());
  return output;
}

extern "C" __declspec(dllexport) char* RetrieveFileAccessInfoByHandle(HANDLE fileHandle) {
  static std::stringstream result;
  result.str("");

  PSECURITY_DESCRIPTOR pSD;
  if (GetSecurityInfo(fileHandle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pSD) == ERROR_SUCCESS) {
    PACL pDacl;
    BOOL bDaclPresent, bDaclDefaulted;

    if (GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted)) {
      if (bDaclPresent) {
        for (DWORD i = 0; i < pDacl->AceCount; ++i) {
          PACE_HEADER pAceHeader;
          if (GetAce(pDacl, i, (LPVOID*)&pAceHeader)) {
            RetrieveAceInfo(pAceHeader, result);
          }
        }
      }
    }
    LocalFree(pSD);
  }
  else {
    result << "Failed to get security information for file." << "\r\n";
  }

  size_t size = result.str().size() + 1;
  char* output = new char[size];
  strcpy_s(output, size, result.str().c_str());
  return output;
}

extern "C" __declspec(dllexport) char* RetrieveKernelObjAccessInfo(HANDLE kernelHandle) {
  static std::stringstream result;
  result.str("");

  // Получение информации безопасности для объекта ядра
  PSECURITY_DESCRIPTOR pSD = NULL;
  DWORD length = 0;

  // Получаем размер буфера
  if (!GetKernelObjectSecurity(kernelHandle, DACL_SECURITY_INFORMATION, NULL, 0, &length)) {
    DWORD lastError = GetLastError();
    if (lastError != ERROR_INSUFFICIENT_BUFFER) {
      result << "Failed to get security descriptor size for kernel object." << "\r\n";
      return NULL;
    }
  }

  pSD = (PSECURITY_DESCRIPTOR)malloc(length);
  if (!pSD) {
    result << "Memory allocation failed." << "\r\n";
    return NULL;
  }

  // Получаем саму информацию безопасности
  if (GetKernelObjectSecurity(kernelHandle, DACL_SECURITY_INFORMATION, pSD, length, &length)) {
    PACL pDacl;
    BOOL bDaclPresent, bDaclDefaulted;

    if (GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted)) {
      if (bDaclPresent) {
        for (DWORD i = 0; i < pDacl->AceCount; ++i) {
          PACE_HEADER pAceHeader;
          if (GetAce(pDacl, i, (LPVOID*)&pAceHeader)) {
            RetrieveAceInfo(pAceHeader, result);
          }
        }
      }
    }
    else {
      result << "Failed to get DACL for kernel object." << "\r\n";
    }
  }
  else {
    result << "Failed to get security information for kernel object." << "\r\n";
  }

  free(pSD);

  // Возвращаем строку с результатом
  size_t size = result.str().size() + 1;
  char* output = new char[size];
  strcpy_s(output, size, result.str().c_str());
  return output;
}

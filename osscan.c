#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma pack(push, 1)
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME 8
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
typedef struct _IMAGE_DOS_HEADER {
  uint16_t e_magic;
  uint16_t e_cblp;
  uint16_t e_cp;
  uint16_t e_crlc;
  uint16_t e_cparhdr;
  uint16_t e_minalloc;
  uint16_t e_maxalloc;
  uint16_t e_ss;
  uint16_t e_sp;
  uint16_t e_csum;
  uint16_t e_ip;
  uint16_t e_cs;
  uint16_t e_lfarlc;
  uint16_t e_ovno;
  uint16_t e_res[4];
  uint16_t e_oemid;
  uint16_t e_oeminfo;
  uint16_t e_res2[10];
  uint32_t e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
typedef struct _IMAGE_FILE_HEADER {
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY {
  uint32_t VirtualAddress;
  uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
typedef struct _IMAGE_OPTIONAL_HEADER64 {
  uint16_t Magic;
  uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint64_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint64_t SizeOfStackReserve;
  uint64_t SizeOfStackCommit;
  uint64_t SizeOfHeapReserve;
  uint64_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
typedef struct _IMAGE_NT_HEADERS64 {
  uint32_t Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
typedef struct _IMAGE_OPTIONAL_HEADER {
  uint16_t Magic;
  uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint32_t BaseOfData;
  uint32_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint32_t SizeOfStackReserve;
  uint32_t SizeOfStackCommit;
  uint32_t SizeOfHeapReserve;
  uint32_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY
  DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
typedef struct _IMAGE_NT_HEADERS {
  uint32_t Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
typedef struct _IMAGE_SECTION_HEADER {
  uint8_t Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    uint32_t PhysicalAddress;
    uint32_t VirtualSize;
  } Misc;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
typedef struct _IMAGE_BASE_RELOCATION {
  uint32_t VirtualAddress;
  uint32_t SizeOfBlock;
  /* WORD TypeOffset[1]; */
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;
typedef struct _IMAGE_RELOCATION {
  union {
    uint32_t VirtualAddress;
    uint32_t RelocCount;
  } DUMMYUNIONNAME;
  uint32_t SymbolTableIndex;
  uint16_t Type;
} IMAGE_RELOCATION, *PIMAGE_RELOCATION;
#pragma pack(pop)

unsigned char s_table[] = {0x0F, 0x87, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xFF, 0x03, 0xFF, 0xFF, 0xFF, 0x4C};

int find_region_rva(FILE *fp, uint64_t *base, uint64_t *rva, uint64_t *raw_ptr,
                    size_t *region_size) {
  IMAGE_DOS_HEADER dos_header;
  IMAGE_NT_HEADERS64 nt_header;
  IMAGE_SECTION_HEADER sec_header;

  fseek(fp, 0, SEEK_SET);
  if (fread(&dos_header, 1, sizeof(dos_header), fp) != sizeof(dos_header)) {
    fputs(">pe read dos header fail\n", stderr);
    return 1;
  }
  if (dos_header.e_magic != 0x5A4D) {
    fputs(">pe header has unexpected magic value\n", stderr);
    return 1;
  }

  fseek(fp, dos_header.e_lfanew, SEEK_SET);
  if (fread(&nt_header, 1, sizeof(nt_header), fp) != sizeof(nt_header)) {
    fputs(">pe read nt header fail\n", stderr);
    return 1;
  }
  if (nt_header.Signature != 0x00004550) {
    fputs(">nt header has unexpected magic value\n", stderr);
    return 1;
  }

  for (int i = 0; i < nt_header.FileHeader.NumberOfSections; i++) {
    if (fread(&sec_header, 1, sizeof(sec_header), fp) != sizeof(sec_header)) {
      fputs(">pe read sec header fail\n", stderr);
      return 1;
    }

    if (strncmp((char *)sec_header.Name, ".text", 5) == 0) {
      *rva = sec_header.VirtualAddress;
      *raw_ptr = sec_header.PointerToRawData;
      *region_size = sec_header.Misc.VirtualSize;
      *base = nt_header.OptionalHeader.ImageBase;
      return 0;
    }
  }

  return 1;
}

int sequence_check(unsigned char *ptr, unsigned char *sig, size_t length) {
  int result = 0;
  for (size_t i = 0; i < length; i++) {
    if (sig[i] == ptr[i] || sig[i] == 0xFF) {
      continue;
    } else {
      result = 1;
      break;
    }
  }
  return result;
}

uint64_t sequence_scan(FILE *fp, uint64_t base, uint64_t rva, uint64_t raw_ptr,
                       size_t region_size, unsigned char *signature,
                       size_t length) {
  uint64_t offset = 0x0;
  uint64_t cur_offset = 0, cur_fileoffset = 0;
  size_t read_size = 4096;
  size_t cur_size = 0, remaining = 0;
  unsigned char *raw_data = (unsigned char *)calloc(read_size, 1);

  for (size_t i = 0, j = 0; i < region_size; i++, j++) {
    cur_offset = i - rva;
    cur_fileoffset = cur_offset + raw_ptr;
    cur_size = region_size - i < read_size ? region_size - i : read_size;

    if (remaining == 0 && cur_size >= length) {
      fseek(fp, cur_fileoffset, SEEK_SET);
      remaining = fread(raw_data, 1, cur_size, fp);
      if (remaining != cur_size) {
        fputs(">read fail, size mismatch\n", stderr);
        free(raw_data);
        return 0;
      }
      j = 0;
    }

    if (sequence_check(raw_data + j, signature, length) == 0) {
      offset = (i - rva) + raw_ptr;
      break;
    }

    remaining--;
  }

  free(raw_data);
  return offset;
}

uint32_t va_offset(FILE *fp, uint64_t va, int64_t offset, uint64_t *result) {
  fseek(fp, va + offset, SEEK_SET);
  if (fread(&(*result), 1, 4, fp) != 4) {
    return 1;
  }
  return 0;
}

size_t find_in_size(FILE *fp, uint64_t offset) {
  uint8_t size = 0;
  uint8_t bytes[3] = {0};
  uint8_t search[] = {0x41, 0x83, 0xF9};

  for (int i = 0; i < 40; i++) {
    fseek(fp, offset - i, SEEK_SET);
    if (fread(bytes, 1, 3, fp) != 3) {
      break;
    }

    if (sequence_check(bytes, search, sizeof(search)) == 0) {
      fseek(fp, offset - i + sizeof(search), SEEK_SET);
      if (fread(&size, 1, 1, fp) != 1) {
        break;
      }
      return (size_t)(size);
    }
  }

  return 0;
}

int scan_table_in(FILE *fp, uint64_t rva, uint64_t raw_ptr, uint64_t table_va,
                  uint64_t table, size_t table_size) {
  int32_t tmp, min_idx = -1;
  int32_t *sizes = (int32_t *)calloc(table_size, 4);
  int32_t *idx = (int32_t *)calloc(table_size, 4);
  int32_t *real_ptr = (int32_t *)calloc(table_size, 4);
  int32_t *ptrs = (int32_t *)calloc(table_size, 4);

  FILE *dump_fp = fopen("log.txt", "w");

  if (dump_fp == NULL) {
    fputs(">cannot open file for logging\n", stderr);
    free(sizes);
    free(ptrs);
    free(idx);
    free(real_ptr);
    return 1;
  }

  for (size_t i = 0; i < table_size; i++) {
    fseek(fp, table + (4 * i), SEEK_SET);
    idx[i] = i;
    if (fread(&ptrs[i], 1, 4, fp) != 4) {
      fputs(">table decode failure\n", stderr);
      free(sizes);
      free(ptrs);
      free(idx);
      free(real_ptr);
      fclose(dump_fp);
      return 1;
    }
  }

  fputs(">descramble table...\n", stdout);
  for (size_t i = 0; i < table_size - 1; i++) {
    min_idx = i;
    for (size_t j = i + 1; j < table_size; j++) {
      if (ptrs[j] < ptrs[min_idx]) {
        min_idx = j;
      }
    }
    if (i != min_idx) {
      tmp = ptrs[min_idx];
      ptrs[min_idx] = ptrs[i];
      ptrs[i] = tmp;
      tmp = idx[min_idx];
      idx[min_idx] = idx[i];
      idx[i] = tmp;
    }
  }

  for (size_t i = 0; i < table_size - 1; i++) {
    sizes[i] = ptrs[i + 1] - ptrs[i];
  }
  sizes[table_size - 1] = table_va - ptrs[table_size - 1];
  for (size_t i = 0; i < table_size; i++) {
    fprintf(stdout, " [+] packet->%03d [0x%X-SIZE: 0x%03X]\n", idx[i], ptrs[i],
            sizes[i]);
    fprintf(dump_fp, " [+] packet->%03d [0x%X-SIZE: 0x%03X]\n", idx[i], ptrs[i],
            sizes[i]);
  }

  fputs("\n>descrambled table:\n---------------\n", stdout);
  fputs("\n>descrambled table:\n---------------\n", dump_fp);

  for (size_t i = 1; i <= table_size; i++) {
    fprintf(stdout, "%03d ", idx[i - 1]);
    fprintf(dump_fp, "%03d ", idx[i - 1]);
    if ((i % 16) == 0) {
      fputs("\n", stdout);
      fputs("\n", dump_fp);
    }
  }

  fprintf(stdout, "\n---------------\ntotal packet: %ld\n", table_size);
  fprintf(dump_fp, "\n---------------\ntotal packet: %ld\n", table_size);

  free(sizes);
  free(ptrs);
  free(idx);
  free(real_ptr);
  fclose(dump_fp);

  return 0;
}

int main(int argc, char *argv[]) {
  FILE *fp;
  size_t region_size = 0, in_size = 0;
  uint64_t base = 0x0, rva = 0x0, raw_ptr = 0x0;
  uint64_t in_table = 0x0, in_head = 0x0;

  if (argc < 2) {
    fputs("usage:\n"
          "\t./osscan <osrs_client_exe_path>\n",
          stderr);
    exit(EXIT_FAILURE);
  }

  const char *path = argv[1];

  fprintf(stdout, ">opening for scan: %s\n", path);

  fp = fopen(path, "rb");
  if (fp == NULL) {
    fputs(">cannot open pe for scanning\n", stderr);
    exit(EXIT_FAILURE);
  }

  if (find_region_rva(fp, &base, &rva, &raw_ptr, &region_size) != 0) {
    fputs(">cannot find scan region\n", stderr);
    fclose(fp);
    exit(EXIT_FAILURE);
  }

  fputs(">processing server packet table\n", stdout);

  in_table = sequence_scan(fp, base, rva, raw_ptr, region_size, s_table,
                           sizeof(s_table));

  if (in_table == 0x0) {
    fputs(">cannot find data table\n", stderr);
    fclose(fp);
    exit(EXIT_FAILURE);
  }

  va_offset(fp, in_table, 17, &in_head);
  in_size = find_in_size(fp, in_table);

  if (in_head == 0x0 || in_table == 0) {
    fputs(">data error decoding table\n", stderr);
    fclose(fp);
    exit(EXIT_FAILURE);
  }

  if (scan_table_in(fp, rva, raw_ptr, in_head, (in_head - rva) + raw_ptr,
                    in_size) != 0) {
    fputs(">table scan fail.\n", stderr);
    fclose(fp);
    exit(EXIT_FAILURE);
  }

  fclose(fp);

  return 0;
}
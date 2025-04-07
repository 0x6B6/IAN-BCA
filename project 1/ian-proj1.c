/**********************************************************
 * Project: Binary code analysis project 1
 * File: ian-proj1.c
 * Date: 21.03.2025
 * Author: Marek Pazúr (xpazurm00)
 * 
 * Description: This program prints out the initial values
 * of global variables defined in given ELF file.
 *********************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <elf.h>
#include <gelf.h>
#include <libelf.h>

int check_file(Elf *elf, char * file) {
	/* Check file type */
	if (elf_kind(elf) != ELF_K_ELF) {
		fprintf(stderr, "File %s is not elf object type\n", file);
		return 1;
	}

	/* Check architecture */
	if (gelf_getclass(elf) != ELFCLASS64) {
		fprintf(stderr, "Only 64-bit architecture ELF is supported\n");
		return 1;
	}

	return 0;
}

intmax_t sign_extend(intmax_t value, int size) {
	/* Shifts to msb */
	int shift = 8  * size - 1;

	/* MSB */
	intmax_t sign_bit = (intmax_t) 1 << shift;

	/* Mask for sign extension */
	intmax_t mask = ~((intmax_t)1 << shift) + 1;

	/* If MSB is signed, extend  */
	if (value & sign_bit) {
		value |= mask;
	}

	return value;
}

int get_symbol_data(Elf *elf, GElf_Sym *symbol, intmax_t *value, int *flags) {
	GElf_Ehdr elf_header;
	Elf_Scn *symbol_section = NULL;
	GElf_Shdr symbol_section_header;
	Elf_Data *symbol_data = NULL;

	/* Check if ELF is DYN or REL type */
	if (gelf_getehdr(elf, &elf_header) == NULL) {
		fprintf(stderr, "Unable to get ELF header - %s\n", elf_errmsg(-1));
		return 1;
	}

	/* Get symbol section information */
	if ((symbol_section = elf_getscn(elf, symbol->st_shndx)) == NULL) {
		fprintf(stderr, "Unable to get symbol section - %s\n", elf_errmsg(-1));
		return 1;
	}
	
	if (gelf_getshdr(symbol_section, &symbol_section_header) != &symbol_section_header) {
		fprintf(stderr, "Unable to get symbol section header - %s\n", elf_errmsg(-1));
		return 1;
	}

	/* Get symbol flags */
	*flags = symbol_section_header.sh_flags;
	
	if ((symbol_data = elf_getdata(symbol_section, NULL)) == NULL) {
		fprintf(stderr, "Unable to get symbol section data - %s\n", elf_errmsg(-1));
		return 1;
	}

	char *data_buffer = symbol_data->d_buf;

	/* Only copy read data when the symbol has any */
	if (data_buffer) {
		/* Different handling for ELF types */
		if (elf_header.e_type == ET_REL) {
			memcpy(value, data_buffer + symbol->st_value, symbol->st_size);
		}
		else {
			memcpy(value, (data_buffer - symbol_section_header.sh_addr) + symbol->st_value, symbol->st_size);
		}
	}

	return 0;
}

int process_elf(Elf *elf) {
	Elf_Scn *symtab_section = NULL;
	GElf_Shdr symtab_header;
	Elf_Data  *symtab_data = NULL;
	bool has_symtab = false;

	/* Print header */
	printf("\033[1m%-10s %-20s %s\033[0m\n", "Size", "Value", "Name");

	/* Get symtab section, header */
	while ((symtab_section = elf_nextscn(elf, symtab_section)) != NULL) {
		if ((gelf_getshdr(symtab_section, &symtab_header)) != &symtab_header) {
			fprintf(stderr, "Unable to get symtab section header - %s\n", elf_errmsg(-1));
			return 1;
		}

		if (symtab_header.sh_type == SHT_SYMTAB || symtab_header.sh_type == SHT_DYNSYM) {
			has_symtab = true;

			if ((symtab_data = elf_getdata(symtab_section, NULL)) == NULL) {
				fprintf(stderr, "Unable to get symtab data - %s\n", elf_errmsg(-1));
				return 1;
			}

			size_t strtab_idx = symtab_header.sh_link;
			intmax_t entries = symtab_header.sh_size / symtab_header.sh_entsize;

			/* Process all symbols in sym table */
			for (intmax_t i = 0; i < entries; ++i) {
				GElf_Sym symbol;

				gelf_getsym(symtab_data, i, &symbol);

				if (
					GELF_ST_BIND(symbol.st_info) == STB_GLOBAL &&
					GELF_ST_TYPE(symbol.st_info) == STT_OBJECT &&
					symbol.st_shndx != SHN_UNDEF && 
					symbol.st_shndx != SHN_ABS &&
					symbol.st_shndx != SHN_COMMON &&
					symbol.st_size >= 1 && symbol.st_size <= 8
					) {
						char *identifier = elf_strptr(elf, strtab_idx, symbol.st_name);
						intmax_t value = 0;
						int flags;

						if (get_symbol_data(elf, &symbol, &value, &flags)) {
							fprintf(stderr, "Error - unable to get symbol data\n");
							return 1;
						}

						if (flags & SHF_WRITE) {
							value = sign_extend(value, symbol.st_size);
							printf("%-10lu %-20ld %s\n", symbol.st_size, value, identifier);
						}
				}
			}
		}
	}

	if (has_symtab == false) {
		fprintf(stderr, "\nError - no .symtab (.dynsym) section found\n");
		return 1;
	}

	return 0;
}

int main(int argc, char **argv) {
	char *file;
	int fd;
	Elf *elf;

	if (argc < 2) {
		fprintf(stderr, "No file specified as a parameter\nusage: %s file-name\n", argv[0]);
		return 1;
	}

	/* Mandatory libelf library setup */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "Elf library init failure- %s\n", elf_errmsg(-1));
		return 1;
	}

	/* Open file & ELF descriptor */
	file = argv[1];

	if ((fd = open(file, O_RDONLY, 0)) < 0) {
		perror("open()");
		return 1;
	}

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		fprintf(stderr, "Unable to begin elf file - %s\n", elf_errmsg(-1));
		close(fd);
		return 1;
	}

	/* Check file type & architecture */
	if (check_file(elf, file)) {
		elf_end(elf);
		close(fd);
		return 1;
	}
	
	/* Process ELF */
	if (process_elf(elf)) {
		elf_end(elf);
		close(fd);
		return 1;
	}

	elf_end(elf);
	close(fd);

	return 0;
}
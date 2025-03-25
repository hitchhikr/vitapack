// VitaPack v1.0
// Written by Franck 'hitchhikr' Charlet.
// Based on the work on the VitaSDK team.

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>
#include <zlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include "zip.h"

#include "vita-export.h"
#include "sce-elf.h"
#include "endian-utils.h"
#include "self.h"
#include "types.h"

#define PSF_MAGIC 0x46535000
#define PSF_VERSION 0x00000101

struct SfoHeader 
{
	uint32_t magic;
	uint32_t version;
	uint32_t keyofs;
	uint32_t valofs;
	uint32_t count;
};

struct SfoEntry
{
	uint16_t nameofs;
	uint8_t  alignment;
	uint8_t  type;
	uint32_t valsize;
	uint32_t totalsize;
	uint32_t dataofs;
};

#define PSF_TYPE_STR 2
#define PSF_TYPE_VAL 4

struct EntryContainer
{
	const char *name;
	int type;
	uint32_t value;
	const char *data;
};

struct EntryContainer g_defaults[] =
{
	{ "ATTRIBUTE", PSF_TYPE_VAL, 0x8000, NULL },
	{ "CATEGORY", PSF_TYPE_STR, 0, "gd" },
	{ "PSP2_SYSTEM_VER", PSF_TYPE_VAL, 0, NULL },
	{ "STITLE", PSF_TYPE_STR, 5, "Home" },
	{ "TITLE_ID", PSF_TYPE_STR, 0, "ABCD66666" },
};

static const char *g_filename = "param.sfo";

int make_sfo(char *name)
{
	FILE *fp;
	int i;
    int j;
    int l;
	char head[8192];
	char keys[8192];
	char data[8192];
	struct SfoHeader *h;
	struct SfoEntry  *e;
	char *k;
	char *d;
	unsigned int align;
	unsigned int keyofs;
	unsigned int count;

    printf("Creating '%s' (181 bytes)...", g_filename);

	memset(head, 0, sizeof(head));
	memset(keys, 0, sizeof(keys));
	memset(data, 0, sizeof(data));

	h = (struct SfoHeader *) head;
	e = (struct SfoEntry *) (head + sizeof(struct SfoHeader));
	k = keys;
	d = data;
	SW(&h->magic, PSF_MAGIC);
	SW(&h->version, PSF_VERSION);
	count = 0;

	for(i = 0; i < (sizeof(g_defaults) / sizeof(struct EntryContainer)); i++)
	{
		SW(&h->count, ++count);
		SH(&e->nameofs, k-keys);
		SW(&e->dataofs, d-data);
		e->alignment = 4;
		e->type = g_defaults[i].type;

		strcpy(k, g_defaults[i].name);
		k += strlen(k) + 1;
		if(e->type == PSF_TYPE_VAL)
		{
			SW(&e->valsize, 4);
			SW(&e->totalsize, 4);
			SW((uint32_t*) d, g_defaults[i].value);
			d += 4;
		}
		else
		{
			int totalsize;
			int valsize = 0;

			if (g_defaults[i].data)
            {
				valsize = strlen(g_defaults[i].data)+1;
            }
			totalsize = (g_defaults[i].value) ? (g_defaults[i].value) : ((valsize + 3) & ~3);
			SW(&e->valsize, valsize);
			SW(&e->totalsize, totalsize);
			memset(d, 0, totalsize);
			
			if (g_defaults[i].data)
            {
				memcpy(d, g_defaults[i].data, valsize);
            }
			d += totalsize;
		}
		e++;
	}

	keyofs = (char*) e - head;
	SW(&h->keyofs, keyofs);
	align = 3 - ((unsigned int) (k-keys) & 3);
	while(align < 3)
	{
		k++;
		align--;
	}
	
	SW(&h->valofs, keyofs + (k - keys));

	fp = fopen(g_filename, "wb");
	if(fp == NULL)
	{
		printf(" Cannot open filename '%s'.\n", g_filename);
		return 0;
	}

	fwrite(head, 1, (char*) e - head, fp);
	fwrite(keys, 1, k - keys, fp);

    j = 12;
    // Copy the name
    for(i = 0; i < 4; i++)
    {
        data[j++] = ' ';
    }

    j = 12;
    l = strlen(name);
    if(l > 4)
    {
        l = 4;
    }
    for(i = 0; i < l; i++)
    {
        data[j + 5] = toupper(name[i]);
        data[j++] = data[j + 5];
    }
    
	fwrite(data, 1, d - data, fp);
	fclose(fp);
    printf(" Done.\n");
    return 1;
}

static int add_file_zip(zip_t *zip, const char *src, const char *dst, int file_number)
{
	struct stat s;
    zip_source_t *src_file;

	if (stat(src,&s))
    {
		return 0;
	}
	if(S_ISREG(s.st_mode))
    {
        src_file = zip_source_file(zip, src, 0, 0);
        if(src_file)
        {   
            zip_file_add(zip, dst, src_file, 0);
            int idx = zip_name_locate(zip, dst, 0);
            zip_set_file_compression(zip, idx, ZIP_CM_DEFLATE, 9);
        }
        else
        {
            return 0;
        }
	}
    else
    {   // symlink etc.
		return 0;
	}
	return 1;
}

void usage(const char **argv)
{
	printf("Usage: %s [-k] input.velf [output.vpk]\n\n", argv[0]);
	printf("       -k = don't remove .vpk trailing data.\n");
	exit(1);
}

int main(int argc, const char **argv)
{
	const char *input_path;
    char output_path[300];
	FILE *fin = NULL;
	FILE *fout = NULL;
    int i;
    int j;
    zip_t *zip;
    int err;
    int total_sections;
    int mangle_zip = 1;
    int min_arg = 1;

    printf("VitaPack v1.1\n");
	printf("Written by hitchhikr of Neural.\n\n");

	if (argc < 2 || argc > 4)
    {
		usage(argv);
    }
    if(argv[1][0] == '-' && toupper(argv[1][1]) == 'K')
    {
        mangle_zip = 0;
        min_arg++;
        if(argc == 2)
        {
            usage(argv);
        }
    }
    
	memset(output_path, 0, sizeof(output_path));
	input_path = argv[min_arg];
	if(argc > (1 + min_arg))
    {
        strcpy(output_path, argv[min_arg + 1]);
	}
    else
    {
        strcpy(output_path, argv[min_arg]);
        i = strlen(output_path);
        while(i)
        {
            if(output_path[i] == '.')
            {
                output_path[++i] = 'v';
                output_path[++i] = 'p';
                output_path[++i] = 'k';
                output_path[++i] = 0;
                break;
            }
            i--;
        }
    }

	fin = fopen(input_path, "rb");
	if (!fin)
    {
		printf("Failed to open input file.");
		goto error;
	}
	fseek(fin, 0, SEEK_END);
	size_t sz = ftell(fin);
	fseek(fin, 0, SEEK_SET);

	char *input = calloc(1, sz);
	if (!input)
    {
		printf("Failed to allocate buffer for input file.");
		goto error;
	}
	if (fread(input, sz, 1, fin) != 1)
    {
		if (feof(fin))
			printf("Unexpected end of file\n");
		else
			printf("Failed to read input file\n");
		goto error;
	}
	fclose(fin);
	fin = NULL;

	Elf32_Ehdr *ehdr = (Elf32_Ehdr*)input;

    int seg = ehdr->e_entry >> 30;
    int off = ehdr->e_entry & 0x3fffffff;
    Elf32_Phdr *phdr = (Elf32_Phdr*)(input + ehdr->e_phoff + seg * ehdr->e_phentsize);
    sce_module_info_raw *info = (sce_module_info_raw *)(input + phdr->p_offset + off);
    info->module_nid = 0;

    printf("Creating 'eboot.bin' from '%s'...", input_path);

	SCE_header hdr = { 0 };
	hdr.magic = 0x454353;           // "SCE\0"
	hdr.version = 3;
	hdr.sdk_type = 0xC0;
	hdr.header_type = 1;
	hdr.elf_filesize = 0;
	hdr.self_offset = 4;
	hdr.appinfo_offset = 0x80;
	hdr.elf_offset = 0x88;
	hdr.phdr_offset = hdr.elf_offset + sizeof(Elf32_Ehdr);
	hdr.phdr_offset = (hdr.phdr_offset + 0xf) & ~0xf; // align
	hdr.shdr_offset = 0;
	hdr.sceversion_offset = 0;
	hdr.controlinfo_size = sizeof(SCE_controlinfo_6);
	hdr.metadata_offset = hdr.controlinfo_size; // ext_header size

	// SCE_header should be ok
	SCE_appinfo appinfo = { 0 };
    appinfo.authid = 0x2F00000000000001ULL;
	appinfo.vendor_id = 0;
	appinfo.self_type = 0;//self_type; // app/user/kernel/sm
	appinfo.version = 0x000000000000;
	appinfo.padding = 0;

	SCE_controlinfo_6 control_6 = { 0 };
	control_6.common.type = 6;
	control_6.common.size = sizeof(control_6);
	control_6.common.unk = 1;
	control_6.is_used = 0;

    total_sections = 0;
	for (int i = 0; i < ehdr->e_phnum; ++i)
    {
		Elf32_Phdr *phdr = (Elf32_Phdr *)(input + ehdr->e_phoff + ehdr->e_phentsize * i);
        if(phdr->p_type != PT_LOOS)
        {
            total_sections++;
        }
	}
	Elf32_Ehdr myhdr = { 0 };
	memcpy(myhdr.e_ident, "\177ELF\1\1\1", 8);
	myhdr.e_type = 0xfe00;          // No relocations
	myhdr.e_machine = 0x28;
	myhdr.e_version = 1;
	myhdr.e_entry = ehdr->e_entry;
	myhdr.e_phoff = 0x34;
    myhdr.e_flags = 0x05001000U;
	myhdr.e_ehsize = 0x34;
	myhdr.e_phentsize = 0x20;
	myhdr.e_phnum = total_sections;

	fout = fopen("eboot.bin", "wb");
	if (!fout)
    {
		printf("\nFailed to open 'eboot.bin'.");
		goto error;
	}

	fseek(fout, hdr.appinfo_offset, SEEK_SET);
	if (fwrite(&appinfo, sizeof(appinfo), 1, fout) != 1)
    {
		printf("\nFailed to write appinfo.");
		goto error;
	}

	fseek(fout, hdr.elf_offset, SEEK_SET);
	fwrite(&myhdr, sizeof(myhdr), 1, fout);

	// Fix the ELF header
    int total = 0;

    printf("\n\nUnpacked sections (%d):\n\n", ehdr->e_phnum);
	for (int i = 0; i < ehdr->e_phnum; ++i)
    {
		Elf32_Phdr *phdr = (Elf32_Phdr*)(input + ehdr->e_phoff + ehdr->e_phentsize * i);
        phdr->p_filesz = (phdr->p_filesz + 0xf) & ~0xf;
        phdr->p_memsz = (phdr->p_memsz + 0xf) & ~0xf;
        printf("Offset: 0x%.08x / Size: %d bytes\n", phdr->p_offset, phdr->p_filesz);
        total += phdr->p_filesz;
        if (phdr->p_align > 0x1000)
        {
            phdr->p_align = 0x1000;
        }
	}
    printf("\nRaw unpacked size: %d bytes\n", total);

	hdr.section_info_offset = hdr.phdr_offset + sizeof(Elf32_Phdr) * (total_sections);
	hdr.controlinfo_offset = hdr.section_info_offset + sizeof(segment_info) * (total_sections);

	uint32_t offset_to_real_elf = hdr.controlinfo_offset + 0x20;

	fseek(fout, hdr.controlinfo_offset, SEEK_SET);
	fwrite(&control_6, sizeof(control_6), 1, fout);

	fseek(fout, offset_to_real_elf, SEEK_SET);

    // Write the SCE sections infos and data
    total = 0;
    j = 0;
    
    // Remove useless data
    memset((unsigned char *) input + phdr->p_offset + myhdr.e_entry + 4, 0, 27);

    for (int i = 0; i < ehdr->e_phnum; ++i)
    {
        Elf32_Phdr *phdr = (Elf32_Phdr*)(input + ehdr->e_phoff + ehdr->e_phentsize * i);
        if(phdr->p_type != PT_LOOS)
        {
            segment_info sinfo = { 0 };
            sinfo.length = phdr->p_filesz;
            sinfo.length = (sinfo.length + 0xf) & ~0xf; // align
            unsigned char *buf = malloc(sinfo.length);
            memset(buf, 0, sinfo.length);
            memcpy(buf, (unsigned char *) input + phdr->p_offset, phdr->p_filesz);
            sinfo.offset = ftell(fout);
            sinfo.compression = 1;
            sinfo.encryption = 2;
            fseek(fout, hdr.section_info_offset + j * sizeof(segment_info), SEEK_SET);
            if(fwrite(&sinfo, sizeof(sinfo), 1, fout) != 1)
            {
                printf("\nFailed to write segment info.");
                free(buf);
                goto error;
            }
            phdr->p_offset = 0;
            fseek(fout, hdr.phdr_offset + (j * sizeof(Elf32_Phdr)), SEEK_SET);
            if (fwrite(phdr, sizeof(*phdr), 1, fout) != 1)
            {
                printf("\nFailed to write phdr.");
                goto error;
            }

            fseek(fout, sinfo.offset, SEEK_SET);
            if (fwrite(buf, sinfo.length, 1, fout) != 1)
            {
                printf("\nFailed to write segment to fself.");
                goto error;
            }
            total += sinfo.length;
           
           free(buf);
        }
        j++;
    }
    printf("Raw stripped size: %d bytes\n", total);

    // Pad the packed data
    int pos = ftell(fout);
    int phony = 0;
    if(pos & 15)
    {
        for(int i = 0; i < (16 - (pos & 15)); i++)
        {
            fwrite(&phony, 1, 1, fout);
        }
    }

	fseek(fout, 0, SEEK_END);
	hdr.self_filesize = ftell(fout);
	hdr.header_len = hdr.self_filesize;

	fseek(fout, 0, SEEK_SET);
	if (fwrite(&hdr, sizeof(hdr), 1, fout) != 1)
    {
		printf("\nFailed to write SCE header.");
		goto error;
	}

	fclose(fout);
    printf("\nDone.\n\n");

    if(!make_sfo(output_path))
    {
		return 1;
    }

    printf("Creating '%s'...", output_path);
    
	zip = zip_open(output_path, ZIP_CREATE | ZIP_TRUNCATE, &err);
	if(!zip)
    {
		printf("\nFailed to create file.");
		return 1;
	}
	if(!add_file_zip(zip, "param.sfo", "sce_sys/param.sfo", 0))
    {
        zip_close(zip);
		printf("\nFailed to add 'sce_sys/param.sfo'.");
		return 1;
	}
	if(!add_file_zip(zip, "eboot.bin", "eboot.bin", 1))
    {
        zip_close(zip);
		printf("\nFailed to add 'eboot.bin'.");
		return 1;
	}
	zip_close(zip);
    printf(" Done.\n");

    remove("eboot.bin");
    remove("param.sfo");

    fin = fopen(output_path, "rb");
    if(fin)
    {
        // Truncate it
        fseek(fin, 0, SEEK_END);
        total = ftell(fin);
        fseek(fin, 0, SEEK_SET);
        if(mangle_zip)
        {
            unsigned char *vkp = (unsigned char *) malloc(total);
            if(vkp)
            {
                fread(vkp, total, 1, fin);
                fclose(fin);
                fout = fopen(output_path, "wb");
                if(fout)
                {
                    total -= 136;
                    fwrite(vkp, total, 1, fout);
                    fclose(fout);
                }
                free(vkp);
            }
            else
            {
                fclose(fin);
            }
            printf("\nFinal size: %d bytes\n", total);
        }
        else
        {
            printf("\nFinal size: %d bytes (Trailing data kept !)\n", total);
        }
    }
    
	return 0;
error:
	if (fin)
		fclose(fin);
	if (fout)
		fclose(fout);
	return 1;
}

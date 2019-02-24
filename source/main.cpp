#include <string.h>
#include <stdio.h>
#include <switch.h>
#include "mbedtls/sha256.h"

bool mainMenu();

enum Partitions : u8
{
	boot0 = 0,
	boot1 = 10,
	rawnand = 20,
	BCPKG21,
	BCPKG22,
	BCPKG23,
	BCPKG24,
	BCPKG25,
	BCPKG26,
	ProdInfo,
	ProdInfoF,
	SAFE,
	USER,
	SYSTEM1,
	SYSTEM2
};

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
	(void)data;
	randomGet(output, len);

	if (olen)
	{
		*olen = len;
	}
	return 0;
}

bool fileExists(const char* path)
{
	FILE* f = fopen(path, "rb");
	if (f)
	{
		fclose(f);
		return true;
	}
	return false;
}

class Incognito
{
public:

	Incognito()
	{		
		if (fsOpenBisStorage(&m_sh, Partitions::ProdInfo))
		{
			printf("error: failed to open cal0 partition.\n");
			m_open = false;
		}
		else
		{
			m_open = true;
		}
	}
	
	~Incognito()
	{
		close();
	}

	bool close()
	{
		if (isOpen())
		{
			fsStorageClose(&m_sh);
			return true;
		}
		return false;
	}

	bool isOpen()
	{
		return m_open;
	}

	char* backupFileName()
	{
		static char filename[32] = "prodinfo.bin";

		if (!fileExists(filename))
		{
			return filename;
		}
		else
		{
			for (int i = 0; i < 99; i++)
			{
				sprintf(filename, "proinfo.bin.%d", i);

				if (!fileExists(filename))
				{
					return filename;
				}
			}
		}
		return NULL;
	}

	bool backup()
	{
		const char* fileName = backupFileName();

		if (!fileName)
		{
			printf("error: failed to get backup file name\n");
			return false;
		}

		u8* buffer = new u8[size()];

		if (fsStorageRead(&m_sh, 0x0, buffer, size()))
		{
			printf("error: failed reading cal0\n");

			delete buffer;
			return false;
		}

		FILE* f = fopen(fileName, "wb+");

		if (!f)
		{
			printf("error: failed to open %s for writing\n", fileName);

			delete buffer;
			return false;
		}

		fwrite(buffer, 1, size(), f);

		delete buffer;
		fclose(f);

		printf("saved backup to %s\n", fileName);
		return true;
	}

	u64 size()
	{
		u64 s = 0;
		fsStorageGetSize(&m_sh, &s);
		return s;
	}

	bool clean()
	{
		if (!backup())
		{
			return false;
		}

		const char junkSerial[] = "XAW00000000000";

		if (fsStorageWrite(&m_sh, 0x0250, junkSerial, strlen(junkSerial)))
		{
			printf("error: failed writing serial\n");
			return false;
		}

		erase(0x0AE0, 0x800); // client cert
		erase(0x3AE0, 0x130); // private key
		erase(0x35E1, 0x006); // deviceId
		erase(0x36E1, 0x006); // deviceId
		erase(0x02B0, 0x180); // device cert
		erase(0x3D70, 0x240); // device cert
		erase(0x3FC0, 0x240); // device key

		writeHash(0x12E0, 0x0AE0, 0x5EA);  // client cert hash
		writeCal0Hash();
		return verify();
	}

	bool import(const char* path)
	{
		FILE* f = fopen(path, "rb");

		if (!f)
		{
			printf("error: could not open %s\n", path);
			return false;
		}

		copy(f, 0x0250, 0x18); // serial
		copy(f, 0x0AE0, 0x800); // client cert
		copy(f, 0x12E0, 0x20); // client cert hash
		copy(f, 0x3AE0, 0x130); // private key
		copy(f, 0x35E1, 0x006); // deviceId
		copy(f, 0x36E1, 0x006); // deviceId
		copy(f, 0x02B0, 0x180); // device cert
		copy(f, 0x3D70, 0x240); // device cert
		copy(f, 0x3FC0, 0x240); // device key

		fclose(f);
		return writeCal0Hash();
	}

	bool verify()
	{
		bool r = verifyHash(0x12E0, 0x0AE0, 0x5EA); // client cert hash
		r &= verifyHash(0x20, 0x0040, calibrationDataSize()); // calibration hash

		return r;
	}

	char* serial()
	{
		static char serialNumber[0x19];

		memset(serialNumber, 0, 0x18);

		if (fsStorageRead(&m_sh, 0x0250, serialNumber, 0x18))
		{
			printf("error: failed reading calibration data\n");
		}

		return serialNumber;
	}
	
	u32 calibrationDataSize()
	{
		return read<u32>(0x08);
	}

	bool writeCal0Hash()
	{
		return writeHash(0x20, 0x0040, calibrationDataSize());
	}
	
	bool writeHash(u64 hashOffset, u64 offset, u64 sz)
	{
		u8* buffer = new u8[sz];

		if (fsStorageRead(&m_sh, offset, buffer, sz))
		{
			printf("error: failed reading calibration data\n");
		}
		else
		{
			u8 hash[0x20];

			mbedtls_sha256(buffer, sz, hash, 0);

			if (fsStorageWrite(&m_sh, hashOffset, hash, sizeof(hash)))
			{
				printf("error: failed writing hash\n");
			}
		}

		delete buffer;
		return true;
	}

	void print(u8* buffer, u64 sz)
	{
		for (u64 i = 0; i < sz; i++)
		{
			printf("%2.2X ", buffer[i]);
		}
		printf("\n");
	}

	bool verifyHash(u64 hashOffset, u64 offset, u64 sz)
	{
		bool result = false;
		u8* buffer = new u8[sz];

		if (fsStorageRead(&m_sh, offset, buffer, sz))
		{
			printf("error: failed reading calibration data\n");
		}
		else
		{
			u8 hash1[0x20];
			u8 hash2[0x20];

			mbedtls_sha256(buffer, sz, hash1, 0);

			if (fsStorageRead(&m_sh, hashOffset, hash2, sizeof(hash2)))
			{
				printf("error: failed reading hash\n");
			}
			else
			{
				if (memcmp(hash1, hash2, sizeof(hash1)))
				{
					printf("error: hash verification failed for %x %d\n", (long)offset, (long)sz);
					print(hash1, 0x20);
					print(hash2, 0x20);
				}
				else
				{
					result = true;
				}
			}
		}

		delete buffer;
		return result;
	}

	template<class T>
	T read(u64 offset)
	{
		T buffer;

		if (fsStorageRead(&m_sh, offset, &buffer, sizeof(T)))
		{
			printf("error: failed reading %d bytes @ %x\n", (long)sizeof(T), (long)offset);
		}

		return buffer;
	}

	bool erase(u64 offset, u64 sz)
	{
		u8 zero = 0;

		for (u64 i = 0; i < sz; i++)
		{
			fsStorageWrite(&m_sh, offset + i, &zero, 1);
		}

		return true;
	}

	bool copy(FILE* f, u64 offset, u64 sz)
	{
		u8* buffer = new u8[size()];

		fseek(f, offset, 0);

		if (!fread(buffer, 1, sz, f))
		{
			printf("error: failed to read %d bytes from %x\n", (long)sz, (long)offset);
			return false;
		}

		fsStorageWrite(&m_sh, offset, buffer, sz);

		delete buffer;

		return true;
	}
	
protected:
	FsStorage m_sh;
	bool m_open;
};

bool end()
{
	printf("Press + to Reebot\n");

	while (appletMainLoop())
	{
		hidScanInput();

		u64 keys = hidKeysDown(CONTROLLER_P1_AUTO);

		if (keys & KEY_PLUS)
		{
			Power::Reboot();
		}
		consoleUpdate(NULL);
	}

	return true;
}

bool confirm()
{
	printf("Are you sure you want to do this?\n");
	printf("Press A to confirm\n");

	while (appletMainLoop())
	{
		hidScanInput();

		u64 keys = hidKeysDown(CONTROLLER_P1_AUTO);

		if (keys & KEY_PLUS || keys & KEY_B || keys & KEY_X || keys & KEY_Y)
		{
			return false;
		}

		if (keys & KEY_A)
		{
			return true;
		}
		consoleUpdate(NULL);
	}
	return false;
}

bool install()
{
	printf("Are you sure you want erase your personal infomation from prodinfo?\n");

	if (!confirm())
	{
		return end();
	}

	Incognito incognito;

	incognito.clean();
	printf("new serial:       %s\n", incognito.serial());
	incognito.close();

	printf("fin, please reboot\n");
	return end();
}

bool verify()
{

	Incognito incognito;

	if (incognito.verify())
	{
		printf("prodinfo verified\n\n");
		return mainMenu();
	}
	else
	{
		printf("error: prodinfo is invalid\n\n");
		return mainMenu();
	}
}

bool restore()
{
	printf("Are you sure you want to import prodinfo.bin?\n");

	if (!confirm())
	{
		return end();
	}

	Incognito incognito;

	if (!incognito.import("prodinfo.bin"))
	{
		printf("error: failed to import prodinfo.bin\n");
		return end();
	}

	printf("new serial:       %s\n", incognito.serial());
	incognito.close();

	printf("fin, please reboot\n");
	return end();
}

void printSerial()
{
	Incognito incognito;

	printf("%s\n", incognito.serial());
	incognito.close();
}

bool mainMenu()
{
	printf("\n\n-------- Main Menu --------\n");
	printf("Press A to install incognito mode\n");
	printf("Press Y to restore prodinfo.bin\n");
	printf("Press X to verify prodinfo NAND\n");
	printf("Press + to exit\n\n");

	while (appletMainLoop())
	{
		hidScanInput();

		u64 keys = hidKeysDown(CONTROLLER_P1_AUTO);

		if (keys & KEY_A)
		{
			return install();
		}

		if (keys & KEY_Y)
		{
			return restore();
		}

		if (keys & KEY_X)
		{
			return verify();
		}

		if (keys & KEY_PLUS)
		{
			break;
		}
		consoleUpdate(NULL);
	}
	return true;
}


int main(int argc, char **argv)
{
	fsInitialize();
	consoleInit(NULL);

	printSerial();

	printf("Warning: This software was written by a not nice person.\n\n");
	
	mainMenu();

	consoleExit(NULL);
	fsExit();
	return 0;
}

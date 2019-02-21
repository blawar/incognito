#include <string.h>
#include <stdio.h>
#include <switch.h>
#include "mbedtls/sha256.h"

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
		static char filename[32] = "sdmc:/prodinfo.bin";

		if (!fileExists(filename))
		{
			return filename;
		}
		else
		{
			for (int i = 0; i < 99; i++)
			{
				sprintf(filename, "sdmc:/proinfo.bin.%d", i);

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
		return writeHash();
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
	
	bool writeHash()
	{
		u8* buffer = new u8[calibrationDataSize()];

		if (fsStorageRead(&m_sh, 0x0040, buffer, calibrationDataSize()))
		{
			printf("error: failed reading calibration data\n");
		}
		else
		{
			u8 hash[0x20];

			mbedtls_sha256(buffer, calibrationDataSize(), hash, 0);

			if (fsStorageWrite(&m_sh, 0x20, hash, sizeof(hash)))
			{
				printf("error: failed writing hash\n");
			}
		}

		delete buffer;
		return true;
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
	
protected:
	FsStorage m_sh;
	bool m_open;
};


int main(int argc, char **argv)
{
	fsInitialize();
    consoleInit(NULL);

	Incognito incognito;

	printf("original serial:  %s\n", incognito.serial());
	incognito.clean();
	printf("new serial:       %s\n", incognito.serial());
	incognito.close();

	printf("fin, please reboot\n");
	printf("press + to exit\n");
	
	while(appletMainLoop())
	{
		hidScanInput();

        u64 kDown = hidKeysDown(CONTROLLER_P1_AUTO);

        if (kDown & KEY_PLUS)
		{
			break;
		}
		consoleUpdate(NULL);
	}

    consoleExit(NULL);
	fsExit();
    return 0;
}

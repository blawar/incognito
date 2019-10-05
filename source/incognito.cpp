#include "incognito.h"
#include <dirent.h>
#include <sys/stat.h>


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

Incognito::Incognito()
{
	if (fsOpenBisStorage(&m_sh, FsBisStorageId_CalibrationBinary))
	{
		printf("error: failed to open cal0 partition.\n");
		m_open = false;
	}
	else
	{
		m_open = true;
	}
}

Incognito::~Incognito()
{
	close();
}

bool Incognito::close()
{
	if (isOpen())
	{
		fsStorageClose(&m_sh);
		return true;
	}
	return false;
}

bool Incognito::isOpen()
{
	return m_open;
}

char* Incognito::backupFileName()
{
	static char filename[32] = "sdmc:/backup/prodinfo.bin";

	if (!fileExists(filename))
	{
		mkdir("sdmc:/backup/", 777);
		return filename;
	}
	else
	{
		for (int i = 0; i < 99; i++)
		{
			sprintf(filename, "sdmc:/backup/prodinfo.bin.%d", i);

			if (!fileExists(filename))
			{
				return filename;
			}
		}
	}
	return NULL;
}

bool Incognito::backup()
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

u64 Incognito::size()
{
	u64 s = 0;
	fsStorageGetSize(&m_sh, &s);
	return s;
}

bool Incognito::clean()
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

	writeHash(0x12E0, 0x0AE0, certSize());  // client cert hash
	writeCal0Hash();
	return verify();
}

bool Incognito::import(const char* path)
{
	FILE* f = fopen(path, "rb");

	if (!f)
	{
		printf("error: could not open %s\n", path);
		return false;
	}

	copy(f, 0x0250, 0x18); // serial
	copy(f, 0x0AD0, 0x04); // client size
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

bool Incognito::verify()
{
	bool r = verifyHash(0x12E0, 0x0AE0, certSize()); // client cert hash
	r &= verifyHash(0x20, 0x0040, calibrationDataSize()); // calibration hash

	return r;
}

char* Incognito::serial()
{
	static char serialNumber[0x19];

	memset(serialNumber, 0, 0x18);

	if (fsStorageRead(&m_sh, 0x0250, serialNumber, 0x18))
	{
		printf("error: failed reading calibration data\n");
	}

	return serialNumber;
}

u32 Incognito::calibrationDataSize()
{
	return read<u32>(0x08);
}

u32 Incognito::certSize()
{
	return read<u32>(0x0AD0);
}

bool Incognito::writeCal0Hash()
{
	return writeHash(0x20, 0x0040, calibrationDataSize());
}

bool Incognito::writeHash(const u64 hashOffset, const u64 offset, const u64 sz)
{
	u8* buffer = new u8[sz];

	if (fsStorageRead(&m_sh, offset, buffer, sz))
	{
		printf("error: failed reading calibration data\n");
	}
	else
	{
		u8 hash[0x20];

		sha256CalculateHash(hash, buffer, sz);

		if (fsStorageWrite(&m_sh, hashOffset, hash, sizeof(hash)))
		{
			printf("error: failed writing hash\n");
		}
	}

	delete buffer;
	return true;
}

void Incognito::print(const u8* buffer, const u64 sz) const
{
	for (u64 i = 0; i < sz; i++)
	{
		printf("%2.2X ", buffer[i]);
	}
	printf("\n");
}

bool Incognito::verifyHash(const u64 hashOffset, const u64 offset, const u64 sz)
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

		sha256CalculateHash(hash1, buffer, sz);

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

bool Incognito::erase(const u64 offset, const u64 sz)
{
	u8 zero = 0;

	for (u64 i = 0; i < sz; i++)
	{
		fsStorageWrite(&m_sh, offset + i, &zero, 1);
	}

	return true;
}

bool Incognito::copy(FILE* f, const u64 offset, const u64 sz)
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


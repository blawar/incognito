#pragma once
#include <switch.h>
#include <stdio.h>
#include <string.h>

class Incognito
{
public:

	Incognito();
	~Incognito();

	bool close();
	bool isOpen();
	char* backupFileName();
	bool backup();
	u64 size();
	bool clean();
	bool import(const char* path);
	bool verify();
	char* serial();
	u32 calibrationDataSize();
	u32 certSize();
	bool writeCal0Hash();
	bool writeHash(const u64 hashOffset, const u64 offset, const u64 sz);
	void print(const u8* buffer, const u64 sz) const;
	bool verifyHash(const u64 hashOffset, const u64 offset, const u64 sz);

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

	bool erase(const u64 offset, const u64 sz);
	bool copy(FILE* f, const u64 offset, const u64 sz);

protected:
	FsStorage m_sh;
	bool m_open;
};

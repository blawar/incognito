#include <switch.h>
#include "incognito.h"

bool mainMenu();

bool end()
{
	printf("Press + to exit\n");

	while (appletMainLoop())
	{
		hidScanInput();

		u64 keys = hidKeysDown(CONTROLLER_P1_AUTO);

		if (keys & KEY_PLUS)
		{
			break;
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

bool backup()
{
	printf("Backing up your prodinfo.bin\n");
	Incognito incognito;
	incognito.backup();
	return end();
	
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

	if (!incognito.import("sdmc:/backup/prodinfo.bin"))
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
	printf("Press B to backup prodinfo.bin only\n");
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
		
		if (keys & KEY_B)
		{
			return backup();
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

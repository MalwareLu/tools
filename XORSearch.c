/*
	29/12/2006 - 16/02/2013
	XORSearch V1.8, search for a XOR, ROL, ROT or SHIFT encoded string in a file
	Use -s to save the XOR, ROL or ROT encoded file containing the string
	Use -l length to limit the number of printed characters (50 by default)
	Use -i to ignore the case when searching
	Use -u to search for Unicode strings (limited support)
	Use -f to provide a file with search strings
	Use -n length to print the length neighbouring charaters (before & after the found keyword)
	Use -h to search for hex strings
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcommings, or todo's ;-)
	- no pipe support (file redirection)
	- file must fit in memory

	History:
		15/01/2007: multiple hits, only printable characters, length argument
		08/08/2007: 1.2: added ROL 1 to 7 encoding
		17/12/2007: 1.3: findfile
		18/04/2009: 1.4: ROT encoding
		12/01/2010: 1.5: added (limited) Unicode support; -n option
		15/01/2010: 1.6: added hex support
		29/10/2012: 1.7: Dropped malloc.h
		16/02/2013: 1.8: Added SHIFT encoding
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#define XSIZE 1024

#define OPR_XOR "XOR"
#define OPR_ROL "ROL"
#define OPR_ROT "ROT"
#define OPR_SHIFT "SHIFT"

#define SEARCHTYPE_ASCII		1
#define SEARCHTYPE_UNICODE	2
#define SEARCHTYPE_HEX			3

int *piFoundIndex;
int *piFoundSize;

int compare(char cX, char cY, int iFlagIgnoreCase)
{
	if (iFlagIgnoreCase && isalpha(cX) && isalpha(cY))
		return tolower(cX) == tolower(cY);
	else
		return cX == cY;
}

// Search algorithm: http://www-igm.univ-mlv.fr/~lecroq/string/node8.html#SECTION0080
void preKmp(char *pcX, int m, int kmpNext[], int iFlagIgnoreCase) {
   int i, j;

   i = 0;
   j = kmpNext[0] = -1;
   while (i < m) {
      while (j > -1 && !compare(pcX[i], pcX[j], iFlagIgnoreCase))
         j = kmpNext[j];
      i++;
      j++;
      if (compare(pcX[i], pcX[j], iFlagIgnoreCase))
         kmpNext[i] = kmpNext[j];
      else
         kmpNext[i] = j;
   }
}

int KMP(char *pcX, int m, char *pcY, int n, int iFlagIgnoreCase) {
   int i, j, kmpNext[XSIZE];
   int iCountFinds = 0;

   /* Preprocessing */
   preKmp(pcX, m, kmpNext, iFlagIgnoreCase);

   /* Searching */
   i = j = 0;
   while (j < n) {
      while (i > -1 && !compare(pcX[i], pcY[j], iFlagIgnoreCase))
         i = kmpNext[i];
      i++;
      j++;
      if (i >= m) {
      	 piFoundIndex[iCountFinds] = j-i;
      	 piFoundSize[iCountFinds++] = m;
         i = kmpNext[i];
      }
   }
   return iCountFinds;
}

long ParseNumericArg(char *szArg)
{
	char *szError;
	long lResult;

	lResult = strtol(szArg, &szError, 0);
	if (*szError != '\0' || lResult == LONG_MIN || lResult == LONG_MAX)
		return -1;
	else
		return lResult;
}

int ParseArgs(int argc, char **argv, int *piSave, int *piMaxLength, int *piIgnoreCase, char **ppcFile, char **ppcSearch, char **ppcSearchFile, int *piUnicode, int *piNeighbourgLength, int *piHex)
{
	int iIterArgv;
	int iCountParameters;
	int iFlagMaxLength;
	int iFlagNeighbourgLength;
	int iFlagSearchFile;
	char *pcFlags;

	iCountParameters = 0;
	iFlagMaxLength = 0;
	iFlagNeighbourgLength = 0;
	iFlagSearchFile = 0;
	*piSave = 0;
	*piMaxLength = -1;
	*piNeighbourgLength = -1;
	*piIgnoreCase = 0;
	*ppcSearch = NULL;
	*ppcSearchFile = NULL;
	*piUnicode = 0;
	*piHex = 0;
  for (iIterArgv = 1; iIterArgv < argc; iIterArgv++)
  {
  	if (argv[iIterArgv][0] == '-')
  	{
  		if (iFlagMaxLength || iFlagSearchFile)
  			return 1;
  		pcFlags = argv[iIterArgv] + 1;
  		while (*pcFlags)
  			switch (*pcFlags++)
  			{
  				case 's':
  					*piSave = 1;
  					break;
  				case 'i':
  					*piIgnoreCase = 1;
  					break;
  				case 'l':
  					iFlagMaxLength = 1;
  					break;
  				case 'f':
  					iFlagSearchFile = 1;
  					break;
  				case 'u':
  					*piUnicode = 1;
  					break;
  				case 'n':
  					iFlagNeighbourgLength = 1;
  					break;
  				case 'h':
  					*piHex = 1;
  					break;
  				default:
  					return 1;
  			}
  	}
  	else if (iFlagMaxLength)
  	{
  		*piMaxLength = ParseNumericArg(argv[iIterArgv]);
  		if (*piMaxLength < 1)
  			return 1;
  		iFlagMaxLength = 0;
  	}
  	else if (iFlagNeighbourgLength)
  	{
  		*piNeighbourgLength = ParseNumericArg(argv[iIterArgv]);
  		if (*piNeighbourgLength < 1)
  			return 1;
  		iFlagNeighbourgLength = 0;
  	}
  	else if (iFlagSearchFile)
  	{
  		*ppcSearchFile = argv[iIterArgv];
  		iFlagSearchFile = 0;
  	}
  	else if (iCountParameters == 0)
  	{
  		*ppcFile = argv[iIterArgv];
  		iCountParameters++;
  	}
  	else if (iCountParameters == 1)
  	{
  		*ppcSearch = argv[iIterArgv];
  		iCountParameters++;
  	}
		else
  		iCountParameters++;
  }
  if (iCountParameters != 2 && *ppcSearchFile == NULL)
  	return 1;
  else if (iCountParameters != 1 && *ppcSearchFile != NULL)
  	return 1;
  else if (*piMaxLength != -1 && *piNeighbourgLength != -1)
  	return 1;
  else if (*piUnicode && *piHex)
  	return 1;
  else
  	return 0;
}

void XOR(unsigned char *pcBuffer, long lSize, unsigned char cXOR)
{
	unsigned char *pcBufferEnd;

	pcBufferEnd = pcBuffer + lSize;
	while (pcBuffer < pcBufferEnd)
		*pcBuffer++ ^= cXOR;
}

void ROL(unsigned char *pcBuffer, long lSize)
{
	unsigned char *pcBufferEnd;

	pcBufferEnd = pcBuffer + lSize;
	while (pcBuffer < pcBufferEnd)
	{
		*pcBuffer = *pcBuffer << 1 | *pcBuffer >> 7;
		pcBuffer++;
	}
}

void ROT(unsigned char *pcBuffer, long lSize)
{
	unsigned char *pcBufferEnd;

	pcBufferEnd = pcBuffer + lSize;
	while (pcBuffer < pcBufferEnd)
	{
		if ((*pcBuffer >= 'a' && *pcBuffer < 'z') || (*pcBuffer >= 'A' && *pcBuffer < 'Z'))
			(*pcBuffer)++;
		else if (*pcBuffer == 'z')
			*pcBuffer = 'a';
		else if (*pcBuffer == 'Z')
			*pcBuffer = 'A';
		pcBuffer++;
	}
}

void SHIFT(unsigned char *pcBuffer, long lSize)
{
	unsigned char *pcBufferEnd;
	unsigned char ucFirstBit;

	pcBufferEnd = pcBuffer + lSize;
	ucFirstBit = *pcBuffer >> 7;
	while (pcBuffer < pcBufferEnd - 1)
	{
		*pcBuffer = *pcBuffer << 1 | *(pcBuffer + 1) >> 7;
		pcBuffer++;
	}
	*(pcBufferEnd - 1) = *(pcBufferEnd - 1) << 1 | ucFirstBit;
}

void SaveFile(char *pcFile, char *sOperation, unsigned char ucXOR, void *pBuffer, long lSize)
{
	char szFileNameSave[XSIZE];
	FILE *fOut;

	snprintf(szFileNameSave, XSIZE, "%s.%s.%02X", pcFile, sOperation, ucXOR);
	if ((fOut = fopen(szFileNameSave, "wb")) == NULL)
		fprintf(stderr, "error opening file %s\n", szFileNameSave);
	else
	{
		if (fwrite(pBuffer, lSize, 1, fOut) != 1)
			fprintf(stderr, "error writing file %s\n", szFileNameSave);
		fclose (fOut);
	}
}

void PrintFinds(int iCountFinds, int iMaxLength, char *sOperation, unsigned char ucOperand, struct stat statFile, void *pBuffer, int iSearchType, int iNeighbourgLength)
{
	int iIter1, iIter2;
	int iMaxPrint;
	int iStart;
	int iStop;
	int iStep;

	for (iIter1 = 0; iIter1 < iCountFinds; iIter1++)
	{
		if (strcmp(sOperation, OPR_ROT))
			printf("Found %s %02X position %04X", sOperation, ucOperand, piFoundIndex[iIter1]);
		else
			printf("Found %s %02d position %04X", sOperation, ucOperand, piFoundIndex[iIter1]);
		if (iNeighbourgLength > 0)
			printf("(-%d): ", iNeighbourgLength);
		else
			printf(": ");
		if (iNeighbourgLength > 0)
		{
			iStep = iSearchType == SEARCHTYPE_UNICODE ? 2 : 1;
			iStart = piFoundIndex[iIter1] - iNeighbourgLength * iStep;
			if (iStart < 0)
				iStart = 0;
			iStop = piFoundIndex[iIter1] + piFoundSize[iIter1] + iNeighbourgLength * iStep;
			if (iStop > statFile.st_size)
				iStop = statFile.st_size;
			for (iIter2 = iStart; iIter2 < iStop; iIter2 += iStep)
				if (SEARCHTYPE_HEX == iSearchType)
					printf("%02X", ((unsigned char *)pBuffer)[iIter2]);
				else
					if (isprint(((unsigned char *)pBuffer)[iIter2]))
						putchar(((unsigned char *)pBuffer)[iIter2]);
					else
						putchar('.');
		}
		else
		{
			iMaxPrint = iMaxLength;
			iStep = iSearchType == SEARCHTYPE_UNICODE ? 2 : 1;
			for (iIter2 = piFoundIndex[iIter1]; iIter2 < statFile.st_size && (SEARCHTYPE_HEX == iSearchType || ((unsigned char *)pBuffer)[iIter2]); iIter2 += iStep)
			{
				if (SEARCHTYPE_HEX == iSearchType)
					printf("%02X", ((unsigned char *)pBuffer)[iIter2]);
				else
					if (isprint(((unsigned char *)pBuffer)[iIter2]))
						putchar(((unsigned char *)pBuffer)[iIter2]);
					else
						putchar('.');
				if (iMaxLength > 0 && --iMaxPrint == 0)
					break;
			}
		}
		putchar('\n');
	}
}

char *strncpy0(char *pszDestination, char *pszSource, size_t stNum)
{
	strncpy(pszDestination, pszSource, stNum);
	pszDestination[stNum - 1] = '\0';
	return pszDestination;
}

int IsHexDigit(char cHexDigit)
{
	return cHexDigit >= '0' && cHexDigit <= '9' || cHexDigit >= 'A' && cHexDigit <= 'F' || cHexDigit >= 'a' && cHexDigit <= 'f';
}

int HexDigitToNibble(char cHexDigit)
{
	if (cHexDigit >= '0' && cHexDigit <= '9')
		return cHexDigit - '0';
	if (cHexDigit >= 'A' && cHexDigit <= 'F')
		return cHexDigit - 'A' + 10;
	if (cHexDigit >= 'a' && cHexDigit <= 'f')
		return cHexDigit - 'a' + 10;
	return -1;
}

int Hexstring2Binary(char *pcHexString, char *pcBinary)
{
	int iCount = 0;

	while ('\0' != *pcHexString && '\0' != *(pcHexString + 1) && iCount < XSIZE)
		if (IsHexDigit(*pcHexString) && IsHexDigit(*(pcHexString + 1)))
		{
			pcBinary[iCount++] = (char) HexDigitToNibble(*pcHexString) * 0x10 + HexDigitToNibble(*(pcHexString + 1));
			pcHexString += 2;
		}
		else
			return -1;
	if ('\0' != *pcHexString)
		return -2;
	else
		return iCount;
}

char *GetSearchString(char *pcArgSearch, char *pcArgSearchFile, int iSearchType, int *piLength)
{
	static char szSearch[XSIZE+1];
	static int iArgSearchReturned;
	static FILE *fSearchFile;
	int iIter;

	if (iArgSearchReturned)
	{
		iArgSearchReturned = 0;
		return NULL;
	}

	if (pcArgSearch == NULL)
	{
		if (fSearchFile == NULL)
			if ((fSearchFile = fopen(pcArgSearchFile, "r")) == NULL)
			{
				fprintf(stderr, "error opening file %s\n", pcArgSearchFile);
				exit(-1);
			}
		if (fgets(szSearch, XSIZE, fSearchFile) == NULL)
		{
			fclose(fSearchFile);
			fSearchFile = NULL;
			return NULL;
		}
		else
		{
			if (szSearch[strlen(szSearch) - 1] == '\n')
				szSearch[strlen(szSearch) - 1] = '\0';
			switch (iSearchType)
			{
				case SEARCHTYPE_ASCII:
					*piLength = strlen(szSearch);
					break;
				case SEARCHTYPE_UNICODE:
					*piLength = 2 * strlen(szSearch);
					for (iIter = XSIZE / 2; iIter > 0; iIter--)
						szSearch[2 * iIter] = szSearch[iIter];
					for (iIter = 1; iIter <= XSIZE; iIter += 2)
						szSearch[iIter] = '\0';
					break;
				case SEARCHTYPE_HEX:
					*piLength = Hexstring2Binary(szSearch, szSearch);
					if (*piLength < 0)
					{
						fprintf(stderr, "Error parsing hex string\n");
						exit(-1);
					}
					break;
				default:
					fprintf(stderr, "Panic: 0001\n");
					exit(-1);
			}
			return szSearch;
		}
	}
	else
	{
		iArgSearchReturned = 1;
		switch (iSearchType)
		{
			case SEARCHTYPE_ASCII:
				strncpy0(szSearch, pcArgSearch, XSIZE);
				*piLength = strlen(szSearch);
				break;
			case SEARCHTYPE_UNICODE:
				strncpy0(szSearch, pcArgSearch, XSIZE / 2);
				*piLength = 2 * strlen(szSearch);
				for (iIter = XSIZE / 2; iIter > 0; iIter--)
					szSearch[2 * iIter] = szSearch[iIter];
				for (iIter = 1; iIter <= XSIZE; iIter += 2)
					szSearch[iIter] = '\0';
				break;
			case SEARCHTYPE_HEX:
				*piLength = Hexstring2Binary(pcArgSearch, szSearch);
				if (*piLength < 0)
				{
					fprintf(stderr, "Error parsing hex string: %s\n", pcArgSearch);
					exit(-1);
				}
				break;
			default:
				fprintf(stderr, "Panic: 0002\n");
				exit(-1);
		}
		return szSearch;
	}
}

main(int argc, char **argv)
{
	FILE *fIn;
	struct stat statFile;
	void *pBuffer;
	unsigned char ucOPRIter;
	char *pcArgFile;
	char *pcArgSearch;
	char *pcArgSearchFile;
	char *pcSearch;
	int iFlagSave;
	int iFlagIgnoreCase;
	int iMaxLength;
	int iCountFinds;
	int iFound;
	int iFlagUnicode;
	int iSearchLength;
	int iNeighbourgLength;
	int iFlagHex;
	int iSearchType;

	if (ParseArgs(argc, argv, &iFlagSave, &iMaxLength, &iFlagIgnoreCase, &pcArgFile, &pcArgSearch, &pcArgSearchFile, &iFlagUnicode, &iNeighbourgLength, &iFlagHex))
	{
		fprintf(stderr, "Usage: XORSearch [-siuh] [-l length] [-n length] [-f search-file] file string\n"
									  "XORSearch V1.8, search for a XOR, ROL, ROT or SHIFT encoded string in a file\n"
										"Use -s to save the XOR, ROL, ROT or SHIFT encoded file containing the string\n"
										"Use -l length to limit the number of printed characters (50 by default)\n"
										"Use -i to ignore the case when searching\n"
										"Use -u to search for Unicode strings (limited support)\n"
										"Use -f to provide a file with search strings\n"
										"Use -n length to print the length neighbouring charaters (before & after the found keyword)\n"
										"Use -h to search for hex strings\n"
										"Options -l and -n are mutually exclusive\n"
										"Options -u and -h are mutually exclusive\n"
									  "Source code put in the public domain by Didier Stevens, no Copyright\n"
									  "Use at your own risk\n"
									  "https://DidierStevens.com\n");
		return -1;
	}
	if (iMaxLength == -1)
		iMaxLength = 50;

	if (iFlagUnicode)
		iSearchType = SEARCHTYPE_UNICODE;
	else if (iFlagHex)
		iSearchType = SEARCHTYPE_HEX;
	else
		iSearchType = SEARCHTYPE_ASCII;

	if (strlen(pcArgFile) >= XSIZE-1)
	{
		fprintf(stderr, "Error: filename is too long\n");
		return -1;
	}

	if (pcArgSearch == NULL)
	{
		if (stat(pcArgSearchFile, &statFile) != 0)
		{
			fprintf(stderr, "error opening file %s\n", pcArgSearchFile);
			return -1;
		}
	}
	else if (strlen(pcArgSearch) >= XSIZE-2)
	{
		fprintf(stderr, "Error: search string is too long\n");
		return -1;
	}

	if (stat(pcArgFile, &statFile) != 0)
	{
		fprintf(stderr, "error opening file %s\n", pcArgFile);
		return -1;
	}

	if ((pBuffer = malloc(statFile.st_size)) == NULL)
	{
		fprintf (stderr, "file %s is too large %ld\n", pcArgFile, statFile.st_size);
		return -1;
	}

	if ((fIn = fopen(pcArgFile, "rb")) == NULL)
	{
		fprintf(stderr, "error opening file %s\n", pcArgFile);
		free (pBuffer);
		return -1;
	}

	if (fread(pBuffer, statFile.st_size, 1, fIn) != 1)
	{
		fprintf(stderr, "error reading file %s\n", pcArgFile);
		fclose (fIn);
		free (pBuffer);
		return -1;
	}

	fclose (fIn);

	if ((piFoundIndex = (int *)malloc(statFile.st_size * sizeof(int))) == NULL)
	{
		fprintf (stderr, "file %s is too large %ld\n", pcArgFile, statFile.st_size);
		free (pBuffer);
		return -1;
	}

	if ((piFoundSize = (int *)malloc(statFile.st_size * sizeof(int))) == NULL)
	{
		fprintf (stderr, "file %s is too large %ld\n", pcArgFile, statFile.st_size);
		free (pBuffer);
		free (piFoundIndex);
		return -1;
	}

	ucOPRIter = 0;

	do
	{
		XOR((unsigned char *) pBuffer, statFile.st_size, ucOPRIter);

		iFound = 0;
		do
		{
			pcSearch = GetSearchString(pcArgSearch, pcArgSearchFile, iSearchType, &iSearchLength);
			if (pcSearch && iSearchLength > 0)
			{
				iCountFinds = KMP(pcSearch, iSearchLength, pBuffer, statFile.st_size, iFlagIgnoreCase);
				if (iCountFinds > 0)
				{
					PrintFinds(iCountFinds, iMaxLength, OPR_XOR, ucOPRIter, statFile, pBuffer, iSearchType, iNeighbourgLength);
					iFound = 1;
				}
			}
		} while (pcSearch);

		if (iFound && iFlagSave)
			SaveFile(pcArgFile, OPR_XOR, ucOPRIter, pBuffer, statFile.st_size);

		XOR((unsigned char *) pBuffer, statFile.st_size, ucOPRIter);
	} while (++ucOPRIter);

	for (ucOPRIter = 1; ucOPRIter < 8; ucOPRIter++)
	{
		ROL((unsigned char *) pBuffer, statFile.st_size);

		iFound = 0;
		do
		{
			pcSearch = GetSearchString(pcArgSearch, pcArgSearchFile, iSearchType, &iSearchLength);
			if (pcSearch && iSearchLength > 0)
			{
				iCountFinds = KMP(pcSearch, iSearchLength, pBuffer, statFile.st_size, iFlagIgnoreCase);
				if (iCountFinds > 0)
				{
					PrintFinds(iCountFinds, iMaxLength, OPR_ROL, ucOPRIter, statFile, pBuffer, iSearchType, iNeighbourgLength);
					iFound = 1;
				}
			}
		} while (pcSearch);

		if (iFound && iFlagSave)
			SaveFile(pcArgFile, OPR_ROL, ucOPRIter, pBuffer, statFile.st_size);
	}
	ROL((unsigned char *) pBuffer, statFile.st_size);

	for (ucOPRIter = 25; ucOPRIter >= 1; ucOPRIter--)
	{
		ROT((unsigned char *) pBuffer, statFile.st_size);

		iFound = 0;
		do
		{
			pcSearch = GetSearchString(pcArgSearch, pcArgSearchFile, iSearchType, &iSearchLength);
			if (pcSearch && iSearchLength > 0)
			{
				iCountFinds = KMP(pcSearch, iSearchLength, pBuffer, statFile.st_size, iFlagIgnoreCase);
				if (iCountFinds > 0)
				{
					PrintFinds(iCountFinds, iMaxLength, OPR_ROT, ucOPRIter, statFile, pBuffer, iSearchType, iNeighbourgLength);
					iFound = 1;
				}
			}
		} while (pcSearch);

		if (iFound && iFlagSave)
			SaveFile(pcArgFile, OPR_ROT, ucOPRIter, pBuffer, statFile.st_size);
	}
	ROT((unsigned char *) pBuffer, statFile.st_size);

	for (ucOPRIter = 1; ucOPRIter < 8; ucOPRIter++)
	{
		SHIFT((unsigned char *) pBuffer, statFile.st_size);

		iFound = 0;
		do
		{
			pcSearch = GetSearchString(pcArgSearch, pcArgSearchFile, iSearchType, &iSearchLength);
			if (pcSearch && iSearchLength > 0)
			{
				iCountFinds = KMP(pcSearch, iSearchLength, pBuffer, statFile.st_size, iFlagIgnoreCase);
				if (iCountFinds > 0)
				{
					PrintFinds(iCountFinds, iMaxLength, OPR_SHIFT, ucOPRIter, statFile, pBuffer, iSearchType, iNeighbourgLength);
					iFound = 1;
				}
			}
		} while (pcSearch);

		if (iFound && iFlagSave)
			SaveFile(pcArgFile, OPR_SHIFT, ucOPRIter, pBuffer, statFile.st_size);
	}

	free(pBuffer);
	free(piFoundIndex);
	free(piFoundSize);

	return 0;
}

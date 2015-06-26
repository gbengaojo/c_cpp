/*---------------------------------------------------------
File: dirspace.c - To find which files are taking up the
   most space on my fast dwindling Windows hard drive

Author: Gbenga Ojo
Origin Date: May 8, 2013
Modifed Date: May 8, 2013
---------------------------------------------------------*/

#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
   DIR *pDir;
   struct dirent *pDirent;
   char *dir = ".";

/*
   if (pDir = opendir(".") == NULL) {
      printf("Cannot open directory '%s'\n", dir);
      return 1;
   }

   if (pDirent = readdir(pDir) == NULL)
      printf("NULL\n");
   else
      printf("not NULL\n");
*/

   pDir = opendir(".");
   pDirent = readdir(pDir);
   // printf("[0x%08x]\n", pDirent);
   printf("[%s]\n", pDirent->d_name);

/*
   while ((pDirent = readdir(pDir) != NULL)) {
      printf("[%s]\n", pDirent->d_name);
   }
*/

   closedir(pDir);
   return 0;
}

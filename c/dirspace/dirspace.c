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

int recurseDirectories(const char *path);

int main(int argc, char *argv[]) {
   int result;

   if (argc < 2) {
      printf("Usage: dirspace <dirname>\n");
      return 1;
   }

   result = recurseDirectories(argv[1]);

   return result;
}

int recurseDirectories(const char *path) {
   DIR *pdir;
   struct stat *fileinfo;
   struct dirent *pdirent;

   if ((pdir = opendir(path)) == NULL) {
      printf("error opening dir %s\n", path);
      return 1;
   }

   while ((pdirent = readdir(pdir)) != NULL) {
      stat(pdirent->d_name, fileinfo);
      if (S_ISDIR(fileinfo->st_mode)) {
         recurseDirectories(pdirent->d_name);
      } else {
         printf("%s\n", pdirent->d_name);
      }
   }

   closedir(pdir);
   return 0;
}

/*
 * tclfiles.c --
 *
 *	Tcl stubs for file system commands moved here to support modules
 */
/*
 * Copyright (C) 1997 Robey Pointer
 * Copyright (C) 1999, 2000, 2001, 2002, 2003, 2004 Eggheads Development Team
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* FIXME: #include mess
#ifndef lint
static const char rcsid[] = "$Id: tclfiles.c,v 1.9 2003/12/11 00:49:10 wcc Exp $";
#endif
*/

static int tcl_getdesc(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  char *s = NULL;

  BADARGS(3, 3, " dir file");
  filedb_getdesc(argv[1], argv[2], &s);
  if (s) {
    Tcl_AppendResult(irp, s, NULL);
    free_null(s);
    return TCL_OK;
  } else {
    Tcl_AppendResult(irp, "filedb access failed", NULL);
    return TCL_ERROR;
  }
}

static int tcl_setdesc(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  BADARGS(4, 4, " dir file desc");
  filedb_setdesc(argv[1], argv[2], argv[3]);
  return TCL_OK;
}

static int tcl_getowner(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  char *s = NULL;

  BADARGS(3, 3, " dir file");
  filedb_getowner(argv[1], argv[2], &s);
  if (s) {
    Tcl_AppendResult(irp, s, NULL);
    free_null(s);
    return TCL_OK;
  } else {
    Tcl_AppendResult(irp, "filedb access failed", NULL);
    return TCL_ERROR;
  }
}

static int tcl_setowner(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  BADARGS(4, 4, " dir file owner");
  filedb_setowner(argv[1], argv[2], argv[3]);
  return TCL_OK;
}

static int tcl_getgots(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  int i;
  char s[10];

  BADARGS(3, 3, " dir file");
  i = filedb_getgots(argv[1], argv[2]);
  sprintf(s, "%d", i);
  Tcl_AppendResult(irp, s, NULL);
  return TCL_OK;
}

static int tcl_setpwd(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  int idx;

  BADARGS(3, 3, " idx dir");
  idx = atoi(argv[1]);
  if ((idx < 0) || (dcc[idx].type != &DCC_FILES)) {
    Tcl_AppendResult(irp, "invalid idx", NULL);
    return TCL_ERROR;
  }
  files_setpwd(idx, argv[2]);

  return TCL_OK;
}

static int tcl_getpwd(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  int idx;

  BADARGS(2, 2, " idx");
  idx = atoi(argv[1]);
  if ((idx < 0) || (dcc[idx].type != &DCC_FILES)) {
    Tcl_AppendResult(irp, "invalid idx", NULL);
    return TCL_ERROR;
  }
  Tcl_AppendResult(irp, dcc[idx].u.file->dir, NULL);

  return TCL_OK;
}

static int tcl_getfiles(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  BADARGS(2, 2, " dir");
  filedb_getfiles(irp, argv[1]);
  return TCL_OK;
}

static int tcl_getdirs(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  BADARGS(2, 2, " dir");
  filedb_getdirs(irp, argv[1]);
  return TCL_OK;
}

static int tcl_hide(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  BADARGS(3, 3, " dir file");
  filedb_change(argv[1], argv[2]);
  return TCL_OK;
}

static int tcl_unhide(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  BADARGS(3, 3, " dir file");
  filedb_change(argv[1], argv[2]);
  return TCL_OK;
}

static int tcl_setflags(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  FILE *fdb;
  filedb_entry *fdbe;
  char *s = NULL, *p, *d;

  BADARGS(3, 4, " dir ?flags ?channel??");
  realloc_strcpy(s, argv[1]);
  if (s[strlen(s) - 1] == '/')
     s[strlen(s) - 1] = 0;
  p = strrchr(s, '/');
  if (p == NULL) {
    p = s;
    d = "";
  } else {
    *p = 0;
    p++;
    d = s;
  }

  fdb = filedb_open(d, 0);
  if (!fdb) {
    Tcl_AppendResult(irp, "-3", NULL);		/* filedb access failed */
    free_null(s);
    return TCL_OK;
  }
  filedb_readtop(fdb, NULL);
  fdbe = filedb_matchfile(fdb, ftell(fdb), p);
  free_null(s);

  if (!fdbe) {
    Tcl_AppendResult(irp, "-1", NULL);	/* No such dir */
    return TCL_OK;
  }
  if (!(fdbe->stat & FILE_DIR)) {
    Tcl_AppendResult(irp, "-2", NULL);	/* Not a dir */
    return TCL_OK;
  }
  if (argc >= 3) {
    struct flag_record fr = {FR_GLOBAL | FR_CHAN, 0, 0, 0, 0, 0};
    char f[100];

    break_down_flags(argv[2], &fr, NULL);
    build_flags(f, &fr, NULL);
    realloc_strcpy(fdbe->flags_req, f);
  } else {
    free_null(fdbe->flags_req);
  }
  if (argc == 4)
    realloc_strcpy(fdbe->chan, argv[3]);

  filedb_updatefile(fdb, fdbe->pos, fdbe, UPDATE_ALL);
  free_fdbe(&fdbe);
  filedb_close(fdb);
  Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_getflags(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  filedb_entry *fdbe;
  char *s = NULL, *p, *d;

  BADARGS(2, 2, " dir");
  realloc_strcpy(s, argv[1]);
  if (s[strlen(s) - 1] == '/')
     s[strlen(s) - 1] = 0;
  p = strrchr(s, '/');
  if (p == NULL) {
    p = s;
    d = "";
  } else {
    *p = 0;
    p++;
    d = s;
  }

  fdbe = filedb_getentry(d, p);
  /* Directory doesn't exist? */
  if (!fdbe ||
      /* Not a directory? */
      !(fdbe->stat & FILE_DIR)) {
    Tcl_AppendResult(irp, "", NULL);
    free_null(s);
    free_fdbe(&fdbe);
    return TCL_OK;
  }
  if (fdbe->flags_req) {
    realloc_strcpy(s, fdbe->flags_req);
    if (s[0] == '-')
      s[0] = 0;
  } else
    s[0] = 0;
  Tcl_AppendElement(irp, s);
  Tcl_AppendElement(irp, fdbe->chan);
  free_null(s);
  free_fdbe(&fdbe);
  return TCL_OK;
}

static int tcl_mkdir(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  FILE *fdb;
  filedb_entry *fdbe;
  char *s = NULL, *t, *d, *p;
  struct flag_record fr = {FR_GLOBAL | FR_CHAN, 0, 0, 0, 0, 0};

  BADARGS(2, 4, " dir ?required-flags ?channel??");
  realloc_strcpy(s, argv[1]);
  if (s[strlen(s) - 1] == '/')
     s[strlen(s) - 1] = 0;
  p = strrchr(s, '/');
  if (p == NULL) {
    p = s;
    d = "";
  } else {
    *p = 0;
    p++;
    d = s;
  }

  fdb = filedb_open(d, 0);
  if (!fdb) {
    Tcl_AppendResult(irp, "-3", NULL);		/* filedb access failed */
    free_null(s);
    return TCL_OK;
  }
  filedb_readtop(fdb, NULL);
  fdbe = filedb_matchfile(fdb, ftell(fdb), p);

  if (!fdbe) {
    t = malloc(strlen(dccdir) + strlen(d) + strlen(p) + 2);
    sprintf(t, "%s%s/%s", dccdir, d, p);
    if (mkdir(t, 0755) != 0) {
      Tcl_AppendResult(irp, "1", NULL);
      free_null(t);
      free_null(s);
      filedb_close(fdb);
      return TCL_OK;
    }
    fdbe = malloc_fdbe();
    fdbe->stat = FILE_DIR;
    realloc_strcpy(fdbe->filename, argv[1]);
    fdbe->uploaded = now;
  } else if (!(fdbe->stat & FILE_DIR)) {
    Tcl_AppendResult(irp, "2", NULL);
    free_fdbe(&fdbe);
    free_null(s);
    filedb_close(fdb);
    return TCL_OK;
  }
  if (argc >= 3) {
    char f[100];

    break_down_flags(argv[2], &fr, NULL);
    build_flags(f, &fr, NULL);
    realloc_strcpy(fdbe->flags_req, f);
  } else if (fdbe->flags_req) {
    free_null(fdbe->flags_req);
  }
  if (argc == 4) {
    realloc_strcpy(fdbe->chan, argv[3]);
  } else
    if (fdbe->chan)
      free_null(fdbe->chan);

  if (fdbe->pos)
      filedb_addfile(fdb, fdbe);
  else
      filedb_updatefile(fdb, fdbe->pos, fdbe, UPDATE_ALL);
  filedb_close(fdb);
  Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

static int tcl_rmdir(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  FILE *fdb;
  filedb_entry *fdbe;
  char *s = NULL, *t, *d, *p;

  BADARGS(2, 2, " dir");
  realloc_strcpy(s, argv[1]);
  if (s[strlen(s) - 1] == '/')
     s[strlen(s) - 1] = 0;
  p = strrchr(s, '/');
  if (p == NULL) {
    p = s;
    d = "";
  } else {
    *p = 0;
    p++;
    d = s;
  }

  fdb = filedb_open(d, 0);
  if (!fdb) {
    Tcl_AppendResult(irp, "1", NULL);
    free_null(s);
    return TCL_OK;
  }
  filedb_readtop(fdb, NULL);
  fdbe = filedb_matchfile(fdb, ftell(fdb), p);

  if (!fdbe) {
    Tcl_AppendResult(irp, "1", NULL);
    filedb_close(fdb);
    free_null(s);
    return TCL_OK;
  }
  if (!(fdbe->stat & FILE_DIR)) {
    Tcl_AppendResult(irp, "1", NULL);
    filedb_close(fdb);
    free_fdbe(&fdbe);
    free_null(s);
    return TCL_OK;
  }
  /* Erase '.filedb' and '.files' if they exist */
  t = malloc(strlen(dccdir) + strlen(d) + strlen(p) + 11);
  sprintf(t, "%s%s/%s/.filedb", dccdir, d, p);
  unlink(t);
  sprintf(t, "%s%s/%s/.files", dccdir, d, p);
  unlink(t);
  sprintf(t, "%s%s/%s", dccdir, d, p);
  free_null(s);
  if (rmdir(t) == 0) {
    filedb_delfile(fdb, fdbe->pos);
    filedb_close(fdb);
    free_fdbe(&fdbe);
    free_null(t);
    Tcl_AppendResult(irp, "0", NULL);
    return TCL_OK;
  }
  free_null(t);
  free_fdbe(&fdbe);
  filedb_close(fdb);
  Tcl_AppendResult(irp, "1", NULL);
  return TCL_OK;
}

static int tcl_mv_cp(Tcl_Interp * irp, int argc, char **argv, int copy)
{
  char *p, *fn = NULL, *oldpath = NULL, *s = NULL, *s1 = NULL;
  char *newfn = NULL, *newpath = NULL;
  int ok = 0, only_first, skip_this;
  FILE *fdb_old, *fdb_new;
  filedb_entry *fdbe_old, *fdbe_new;
  long where;

  BADARGS(3, 3, " oldfilepath newfilepath");
  realloc_strcpy(fn, argv[1]);
  p = strrchr(fn, '/');
  if (p != NULL) {
    *p = 0;
    realloc_strcpy(s, fn);
    strcpy(fn, p + 1);
    if (!resolve_dir("/", s, &oldpath, -1)) {
      /* Tcl can do * anything */
      Tcl_AppendResult(irp, "-1", NULL);	/* Invalid source */
      free_null(fn);
      free_null(oldpath);
      return TCL_OK;
    }
    free_null(s);
  } else
    realloc_strcpy(oldpath, "/");
  realloc_strcpy(s, argv[2]);
  if (!resolve_dir("/", s, &newpath, -1)) {
    /* Destination is not just a directory */
    p = strrchr(s, '/');
    if (!p) {
      realloc_strcpy(newfn, s);
      s[0] = 0;
    } else {
      *p = 0;
      realloc_strcpy(newfn, p + 1);
    }
    free_null(newpath);
    if (!resolve_dir("/", s, &newpath, -1)) {
      Tcl_AppendResult(irp, "-2", NULL);	/* Invalid desto */
      free_null(newpath);
      free_null(s);
      free_null(newfn);
      return TCL_OK;
    }
  } else
    realloc_strcpy(newfn, "");
  free_null(s);

  /* Stupidness checks */
  if ((!strcmp(oldpath, newpath)) &&
      (!newfn[0] || !strcmp(newfn, fn))) {
    free_null(newfn);
    free_null(fn);
    free_null(oldpath);
    free_null(newpath);
    Tcl_AppendResult(irp, "-3", NULL);	/* Stupid copy to self */
    return TCL_OK;
  }
  /* Be aware of 'cp * this.file' possibility: ONLY COPY FIRST ONE */
  if ((strchr(fn, '?') || strchr(fn, '*')) && newfn[0])
    only_first = 1;
  else
    only_first = 0;

  fdb_old = filedb_open(oldpath, 0);
  if (!strcmp(oldpath, newpath))
    fdb_new = fdb_old;
  else
    fdb_new = filedb_open(newpath, 0);
  if (!fdb_old || !fdb_new) {
    free_null(newfn);
    free_null(fn);
    free_null(oldpath);
    free_null(newpath);
    if (fdb_old)
      filedb_close(fdb_old);
    else if (fdb_new)
      filedb_close(fdb_new);
    Tcl_AppendResult(irp, "-5", NULL);	/* DB access failed */
    return -1;
  }

  filedb_readtop(fdb_old, NULL);
  fdbe_old = filedb_matchfile(fdb_old, ftell(fdb_old), fn);
  if (!fdbe_old) {
    free_null(newfn);
    free_null(fn);
    free_null(oldpath);
    free_null(newpath);
    if (fdb_new != fdb_old)
      filedb_close(fdb_new);
    filedb_close(fdb_old);
    Tcl_AppendResult(irp, "-4", NULL);  /* No match */
    return -2;
  }
  while (fdbe_old) {
    where = ftell(fdb_old);
    skip_this = 0;
    if (!(fdbe_old->stat & (FILE_HIDDEN | FILE_DIR))) {
      s = malloc(strlen(dccdir) + strlen(oldpath)
		  + strlen(fdbe_old->filename) + 2);
      s1 = malloc(strlen(dccdir) + strlen(newpath)
		   + strlen(newfn[0] ? newfn : fdbe_old->filename) + 2);
      sprintf(s, "%s%s%s%s", dccdir, oldpath,
	      oldpath[0] ? "/" : "", fdbe_old->filename);
      sprintf(s1, "%s%s%s%s", dccdir, newpath,
	      newpath[0] ? "/" : "", newfn[0] ? newfn : fdbe_old->filename);
      if (!strcmp(s, s1)) {
	Tcl_AppendResult(irp, "-3", NULL); /* Stupid copy to self */
	skip_this = 1;
      }
      /* Check for existence of file with same name in new dir */
      filedb_readtop(fdb_new, NULL);
      fdbe_new = filedb_matchfile(fdb_new, ftell(fdb_new),
				  newfn[0] ? newfn : fdbe_old->filename);
      if (fdbe_new) {
	/* It's ok if the entry in the new dir is a normal file (we'll
	 * just scrap the old entry and overwrite the file) -- but if
	 * it's a directory, this file has to be skipped.
	 */
	if (fdbe_new->stat & FILE_DIR) {
	  /* Skip */
	  skip_this = 1;
	} else {
	  filedb_delfile(fdb_new, fdbe_new->pos);
	}
	free_fdbe(&fdbe_new);
      }
      if (!skip_this) {
        if ((copy ? copyfile(s, s1) : movefile(s, s1)) == 0) {
	  /* Raw file moved okay: create new entry for it */
	  ok++;
	  fdbe_new = malloc_fdbe();
	  fdbe_new->stat = fdbe_old->stat;
	  /* We don't have to worry about any entries to be
	   * NULL, because realloc_strcpy takes care of that.
	   */
	  realloc_strcpy(fdbe_new->flags_req, fdbe_old->flags_req);
	  realloc_strcpy(fdbe_new->chan, fdbe_old->chan);
	  realloc_strcpy(fdbe_new->filename, fdbe_old->filename);
	  realloc_strcpy(fdbe_new->desc, fdbe_old->desc);
	  if (newfn[0])
	    realloc_strcpy(fdbe_new->filename, newfn);
	  realloc_strcpy(fdbe_new->uploader, fdbe_old->uploader);
	  fdbe_new->uploaded = fdbe_old->uploaded;
	  fdbe_new->size = fdbe_old->size;
	  fdbe_new->gots = fdbe_old->gots;
	  filedb_addfile(fdb_new, fdbe_new);
	  if (!copy)
	    filedb_delfile(fdb_old, fdbe_old->pos);
	  free_fdbe(&fdbe_new);
	}
      }
      free_null(s);
      free_null(s1);
    }
    free_fdbe(&fdbe_old);
    fdbe_old = filedb_matchfile(fdb_old, where, fn);
    if (ok && only_first) {
      free_fdbe(&fdbe_old);
    }
  }
  if (fdb_old != fdb_new)
    filedb_close(fdb_new);
  filedb_close(fdb_old);
  if (!ok)
    Tcl_AppendResult(irp, "-4", NULL);	/* No match */
  else {
    char x[30];

    sprintf(x, "%d", ok);
    Tcl_AppendResult(irp, x, NULL);
  }
  free_null(newfn);
  free_null(fn);
  free_null(oldpath);
  free_null(newpath);
  return TCL_OK;
}

static int tcl_mv(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  return tcl_mv_cp(irp, argc, argv, 0);
}

static int tcl_cp(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  return tcl_mv_cp(irp, argc, argv, 1);
}

static int tcl_fileresend_send(ClientData cd, Tcl_Interp *irp, int argc,
	       		       char *argv[], int resend)
{
  int i, idx;
  char s[21];

  BADARGS(3, 4, " idx filename ?nick?");
  idx = atoi(argv[1]);
  if (idx < 0 || dcc[idx].type != &DCC_FILES) {
    Tcl_AppendResult(irp, "invalid idx", NULL);
    return TCL_ERROR;
  }
  if (argc == 4)
     i = files_reget(idx, argv[2], argv[3], resend);
  else
     i = files_reget(idx, argv[2], "", resend);
  sprintf(s, "%d", i);
  Tcl_AppendResult(irp, s, NULL);
  return TCL_OK;
}

static int tcl_fileresend(ClientData cd, Tcl_Interp *irp, int argc,
                          char *argv[])
{
  return tcl_fileresend_send(cd, irp, argc, argv, 1);
}

static int tcl_filesend(ClientData cd, Tcl_Interp *irp, int argc, char *argv[])
{
  return tcl_fileresend_send(cd, irp, argc, argv, 0);
}

static tcl_cmds mytcls[] =
{
  {"getdesc",		tcl_getdesc},
  {"getowner",		tcl_getowner},
  {"setdesc",		tcl_setdesc},
  {"setowner",		tcl_setowner},
  {"getgots",		tcl_getgots},
  {"getpwd",		tcl_getpwd},
  {"setpwd",		tcl_setpwd},
  {"getfiles",		tcl_getfiles},
  {"getdirs",		tcl_getdirs},
  {"hide",		tcl_hide},
  {"unhide",		tcl_unhide},
  {"filesend",		tcl_filesend},
  {"fileresend",	tcl_fileresend},
  {"mkdir",		tcl_mkdir},
  {"rmdir",		tcl_rmdir},
  {"cp",		tcl_cp},
  {"mv",		tcl_mv},
  {"getflags",		tcl_getflags},
  {"setflags",		tcl_setflags},
  {NULL,		NULL}
};


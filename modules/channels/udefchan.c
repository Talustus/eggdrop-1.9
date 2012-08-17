/*
 * udefchan.c --
 *
 *	user definable channel flags/settings
 */
/*
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
static const char rcsid[] = "$Id: udefchan.c,v 1.7 2003/12/11 00:49:10 wcc Exp $";
#endif
*/

static int getudef(struct udef_chans *ul, char *name)
{
  int val = 0;

  for (; ul; ul = ul->next)
    if (!strcasecmp(ul->chan, name)) {
      val = ul->value;
      break;
    }
  return val;
}

static int ngetudef(char *name, char *chan)
{
  struct udef_struct *l;
  struct udef_chans *ll;

  for (l = udef; l; l = l->next)
    if (!strcasecmp(l->name, name)) {
      for (ll = l->values; ll; ll = ll->next)
        if (!strcasecmp(ll->chan, chan))
          return ll->value;
      break;
    }
  return 0;
}

static void setudef(struct udef_struct *us, char *name, int value)
{
  struct udef_chans *ul, *ul_last = NULL;

  for (ul = us->values; ul; ul_last = ul, ul = ul->next)
    if (!strcasecmp(ul->chan, name)) {
      ul->value = value;
      return;
    }

  ul = malloc(sizeof(struct udef_chans));
  ul->chan = strdup(name);
  ul->value = value;
  ul->next = NULL;
  if (ul_last)
    ul_last->next = ul;
  else
    us->values = ul;
}

static void initudef(int type, char *name, int defined)
{
  struct udef_struct *ul, *ul_last = NULL;

  if (strlen(name) < 1)
    return;

  for (ul = udef; ul; ul_last = ul, ul = ul->next)
    if (ul->name && !strcasecmp(ul->name, name)) {
      if (defined) {
        putlog(LOG_DEBUG, "*", "UDEF: %s defined", ul->name);
        ul->defined = 1;
      }
      return;
    }

  putlog(LOG_DEBUG, "*", "Creating %s (type %d)", name, type);
  ul = malloc(sizeof(struct udef_struct));
  ul->name = strdup(name);
  if (defined)
    ul->defined = 1;
  else
    ul->defined = 0;
  ul->type = type;
  ul->values = NULL;
  ul->next = NULL;
  if (ul_last)
    ul_last->next = ul;
  else
    udef = ul;
}

static void free_udef(struct udef_struct *ul)
{
  struct udef_struct *ull;

  for (; ul; ul = ull) {
    ull = ul->next;
    free_udef_chans(ul->values, ul->type);
    free(ul->name);
    free(ul);
  }
}

static void free_udef_chans(struct udef_chans *ul, int type)
{
  struct udef_chans *ull;

  for (; ul; ul = ull) {
    ull = ul->next;
	if (type == UDEF_STR && ul->value) {
		free((void *)ul->value);
	}
    free(ul->chan);
    free(ul);
  }
}

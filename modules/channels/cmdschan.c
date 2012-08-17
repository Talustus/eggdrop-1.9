/*
 * cmdschan.c --
 *
 *	commands from a user via dcc that cause server interaction
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
static const char rcsid[] = "$Id: cmdschan.c,v 1.20 2003/12/11 00:49:10 wcc Exp $";
#endif
*/

#include <ctype.h>

static struct flag_record user	 = {FR_GLOBAL | FR_CHAN, 0, 0, 0, 0, 0};
static struct flag_record victim = {FR_GLOBAL | FR_CHAN, 0, 0, 0, 0, 0};


static void cmd_pls_mask(char type, struct userrec *u, int idx, char *par)
{
  char *chname, *who, s[UHOSTLEN], s1[UHOSTLEN], *p, *p_expire, *cmd;
  unsigned long int expire_time = 0, expire_foo;
  int sticky = 0;
  struct chanset_t *chan = NULL;
  module_entry *me;

  cmd = type == 'b' ? "ban" : type == 'e' ? "exempt" : "invite";
  if (!par[0]) {
    dprintf(idx, "Usage: +%s <hostmask> [channel] [%%<XdXhXm>] [reason]\n", cmd);
    return;
  }
  who = newsplit(&par);
  if (par[0] && strchr(CHANMETA, par[0]))
    chname = newsplit(&par);
  else
    chname = 0;
  if (chname || !(u->flags & USER_MASTER)) {
    if (!chname)
      chname = dcc[idx].u.chat->con_chan;
    get_user_flagrec(u, &user, chname);
    chan = findchan_by_dname(chname);
    /* *shrug* ??? (guppy:10Feb1999) */
    if (!chan) {
      dprintf(idx, _("That channel doesn't exist!\n"));
      return;
    } else if (!glob_op(user) && !chan_op(user)) {
      dprintf(idx, _("You don't have access to set %ss on %s.\n"), cmd, chname);
      return;
    }
  } else
    chan = 0;
  /* Added by Q and Solal -- Requested by Arty2, special thanx :) */
  if (par[0] == '%') {
    p = newsplit(&par);
    p_expire = p + 1;
    while (*(++p) != 0) {
      switch (tolower(*p)) {
	case 'd':
	  *p = 0;
	  expire_foo = strtol(p_expire, NULL, 10);
	  if (expire_foo > 365)
	    expire_foo = 365;
	  expire_time += 86400 * expire_foo;
	  p_expire = p + 1;
	  break;
	case 'h':
	  *p = 0;
	  expire_foo = strtol(p_expire, NULL, 10);
	  if (expire_foo > 8760)
	    expire_foo = 8760;
	  expire_time += 3600 * expire_foo;
	  p_expire = p + 1;
	  break;
	case 'm':
	  *p = 0;
	  expire_foo = strtol(p_expire, NULL, 10);
	  if (expire_foo > 525600)
	    expire_foo = 525600;
	  expire_time += 60 * expire_foo;
	  p_expire = p + 1;
      }
    }
  }
  if (!par[0])
    par = "requested";
  else if (strlen(par) > MASKREASON_MAX)
    par[MASKREASON_MAX] = 0;
  if (strlen(who) > UHOSTMAX - 4)
    who[UHOSTMAX - 4] = 0;
  /* Fix missing ! or @ BEFORE checking against myself */
  if (!strchr(who, '!')) {
    if (!strchr(who, '@'))
      snprintf(s, sizeof s, "%s!*@*", who);	/* Lame nick ban */
    else
      snprintf(s, sizeof s, "*!%s", who);
  } else if (!strchr(who, '@'))
    snprintf(s, sizeof s, "%s@*", who);	/* brain-dead? */
  else
    strlcpy(s, who, sizeof s);
  if ((me = module_find("server", 0, 0)) && me->funcs)
    snprintf(s1, sizeof s1, "%s!%s", (char *)(me->funcs[SERVER_BOTNAME]),
	     (char *)(me->funcs[SERVER_BOTUSERHOST]));
  else
    s1[0] = 0;
  if (type == 'b' && s1[0] && wild_match(s, s1)) {
    dprintf(idx, _("I'm not going to ban myself.\n"));
    putlog(LOG_CMDS, "*", "#%s# attempted +ban %s", dcc[idx].nick, s);
    return;
  }
  /* IRC can't understand bans longer than 70 characters */
  if (strlen(s) > 70) {
    s[69] = '*';
    s[70] = 0;
  }
  if (chan) {
    u_addmask(type, chan, s, dcc[idx].nick, par,
	      expire_time ? now + expire_time : 0, 0);
    if (par[0] == '*') {
      sticky = 1;
      par++;
      putlog(LOG_CMDS, "*", "#%s# (%s) +%s %s %s (%s) (sticky)",
	     dcc[idx].nick, dcc[idx].u.chat->con_chan, cmd, s, chan->dname, par);
      dprintf(idx, "New %s sticky %s: %s (%s)\n", chan->dname, cmd, s, par);
    } else {
      putlog(LOG_CMDS, "*", "#%s# (%s) +%s %s %s (%s)", dcc[idx].nick,
	     dcc[idx].u.chat->con_chan, cmd, s, chan->dname, par);
      dprintf(idx, "New %s %s: %s (%s)\n", chan->dname, cmd, s, par);
    }
    if (type == 'e' || type == 'I') {
      add_mode(chan, '+', type, s);
    /* Avoid unnesessary modes if you got +dynamicbans, and there is
     * no reason to set mode if irc.mod aint loaded. (dw 001120)
     */
    }  else if ((me = module_find("irc", 0, 0)))
      (me->funcs[IRC_CHECK_THIS_BAN])(chan, s, sticky);
  } else {
    u_addmask(type, NULL, s, dcc[idx].nick, par,
	      expire_time ? now + expire_time : 0, 0);
    if (par[0] == '*') {
      sticky = 1;
      par++;
      putlog(LOG_CMDS, "*", "#%s# (GLOBAL) +%s %s (%s) (sticky)",
	     dcc[idx].nick, cmd, s, par);
      dprintf(idx, "New sticky %s: %s (%s)\n", cmd, s, par);
    } else {
      putlog(LOG_CMDS, "*", "#%s# (GLOBAL) +%s %s (%s)", dcc[idx].nick,
	     cmd, s, par);
      dprintf(idx, "New %s: %s (%s)\n", cmd, s, par);
    }
    if ((me = module_find("irc", 0, 0)))
      for (chan = chanset; chan != NULL; chan = chan->next) {
	if (type == 'b')
	  (me->funcs[IRC_CHECK_THIS_BAN])(chan, s, sticky);
	else
	  add_mode(chan, '+', type, s);
      }
  }
}

static void cmd_pls_ban(struct userrec *u, int idx, char *par)
{
  cmd_pls_mask('b', u, idx, par);
}

static void cmd_pls_exempt(struct userrec *u, int idx, char *par)
{
  if (!use_exempts) {
    dprintf(idx,
	    _("This command can only be used with use-exempts enabled.\n"));
    return;
  }
  cmd_pls_mask('e', u, idx, par);
}

static void cmd_pls_invite(struct userrec *u, int idx, char *par)
{
  if (!use_invites) {
    dprintf(idx,
	    _("This command can only be used with use-invites enabled.\n"));
    return;
  }
  cmd_pls_mask('I', u, idx, par);
}

static void cmd_mns_mask(char type, struct userrec *u, int idx, char *par)
{
  int i = 0, j;
  struct chanset_t *chan = NULL;
  char s[UHOSTLEN], *who, *chname, *cmd, *mask;
  masklist *m;

  cmd = type == 'b' ? "ban" : type == 'e' ? "exempt" : "invite";
  if (!par[0]) {
    dprintf(idx, "Usage: -%s <hostmask> [channel]\n", cmd);
    return;
  }
  who = newsplit(&par);
  if (par[0] && strchr(CHANMETA, par[0]))
    chname = newsplit(&par);
  else
    chname = dcc[idx].u.chat->con_chan;
  if (chname || !(u->flags & USER_MASTER)) {
    if (!chname)
      chname = dcc[idx].u.chat->con_chan;
    get_user_flagrec(u, &user, chname);
    if (!glob_op(user) && !chan_op(user))
      return;
  }
  strlcpy(s, who, sizeof s);
  i = u_delmask(type, NULL, s, (u->flags & USER_MASTER));
  if (i > 0) {
    if (lastdeletedmask)
      mask = lastdeletedmask;
    else
      mask = s;
    putlog(LOG_CMDS, "*", "#%s# -%s %s", dcc[idx].nick, cmd, mask);
    dprintf(idx, "%s %s: %s\n", _("Removed"), cmd, s);
    for (chan = chanset; chan != NULL; chan = chan->next)
      add_mode(chan, '-', type, mask);
    return;
  }
  /* Channel-specific ban? */
  if (chname)
    chan = findchan_by_dname(chname);
  if (chan) {
    m = type == 'b' ? chan->channel.ban :
        type == 'e' ? chan->channel.exempt : chan->channel.invite;
    if ((i = atoi(who)) > 0) {
      snprintf(s, sizeof s, "%d", i);
      j = u_delmask(type, chan, s, 1);
      if (j > 0) {
        if (lastdeletedmask)
          mask = lastdeletedmask;
        else
          mask = s;
	putlog(LOG_CMDS, "*", "#%s# (%s) -%s %s", dcc[idx].nick, chan->dname,
               cmd, mask);
	dprintf(idx, _("Removed %1$s channel %2$s: %3$s\n"), chan->dname, cmd,
                mask);
	add_mode(chan, '-', type, mask);
	return;
      }
      i = 0;
      for (; m && m->mask && m->mask[0]; m = m->next) {
	if ((!u_equals_mask(type == 'b' ? global_bans : type == 'e' ? global_exempts :
	      global_invites, m->mask)) &&
	    (!u_equals_mask(type == 'b' ? chan->bans : type == 'e' ? chan->exempts :
	      chan->invites, m->mask))) {
	  i++;
	  if (i == -j) {
	    add_mode(chan, '-', type, m->mask);
	    dprintf(idx, "%s %s '%s' on %s.\n", _("Removed"), cmd,
		    m->mask, chan->dname);
	    putlog(LOG_CMDS, "*", "#%s# (%s) -%s %s [on channel]",
		   dcc[idx].nick, dcc[idx].u.chat->con_chan, cmd, who);
	    return;
	  }
	}
      }
    } else {
      j = u_delmask(type, chan, who, 1);
      if (j > 0) {
	putlog(LOG_CMDS, "*", "#%s# (%s) -%s %s", dcc[idx].nick,
	       dcc[idx].u.chat->con_chan, cmd, who);
	dprintf(idx, _("Removed %1$s channel %2$s: %3$s\n"), chname, cmd, who);
	add_mode(chan, '-', type, who);
	return;
      }
      for (; m && m->mask && m->mask[0]; m = m->next) {
	if (!irccmp(m->mask, who)) {
	  add_mode(chan, '-', type, m->mask);
	  dprintf(idx, "%s %s '%s' on %s.\n",
		  _("Removed"), cmd, m->mask, chan->dname);
	  putlog(LOG_CMDS, "*", "#%s# (%s) -%s %s [on channel]",
		 dcc[idx].nick, dcc[idx].u.chat->con_chan, cmd, who);
	  return;
	}
      }
    }
  }
  dprintf(idx, _("No such %1$s.\n"), cmd);
}

static void cmd_mns_ban(struct userrec *u, int idx, char *par)
{
  cmd_mns_mask('b', u, idx, par);
}

static void cmd_mns_exempt(struct userrec *u, int idx, char *par)
{
  if (!use_exempts) {
    dprintf(idx,
	    _("This command can only be used with use-exempts enabled.\n"));
    return;
  }
  cmd_mns_mask('e', u, idx, par);
}

static void cmd_mns_invite(struct userrec *u, int idx, char *par)
{
  if (!use_invites) {
    dprintf(idx,
	    _("This command can only be used with use-invites enabled.\n"));
    return;
  }
  cmd_mns_mask('I', u, idx, par);
}

static void cmd_bans(struct userrec *u, int idx, char *par)
{
  if (!strcasecmp(par, "all")) {
    putlog(LOG_CMDS, "*", "#%s# bans all", dcc[idx].nick);
    tell_bans(idx, 1, "");
  } else {
    putlog(LOG_CMDS, "*", "#%s# bans %s", dcc[idx].nick, par);
    tell_bans(idx, 0, par);
  }
}

static void cmd_exempts (struct userrec *u, int idx, char *par)
{
  if (!use_exempts) {
    dprintf(idx,
            _("This command can only be used with use-exempts enabled.\n"));
    return;
  }
  if (!strcasecmp(par, "all")) {
    putlog(LOG_CMDS, "*", "#%s# exempts all", dcc[idx].nick);
    tell_exempts(idx, 1, "");
  } else {
    putlog(LOG_CMDS, "*", "#%s# exempts %s", dcc[idx].nick, par);
    tell_exempts(idx, 0, par);
  }
}

static void cmd_invites (struct userrec *u, int idx, char *par)
{
  if (!use_invites) {
    dprintf(idx,
            _("This command can only be used with use-invites enabled.\n"));
    return;
  }
  if (!strcasecmp(par, "all")) {
    putlog(LOG_CMDS, "*", "#%s# invites all", dcc[idx].nick);
    tell_invites(idx, 1, "");
  } else {
    putlog(LOG_CMDS, "*", "#%s# invites %s", dcc[idx].nick, par);
    tell_invites(idx, 0, par);
  }
}

static void cmd_info(struct userrec *u, int idx, char *par)
{
  char s[512], *chname, *s1;
  int locked = 0;

  if (!use_info) {
    dprintf(idx, _("Info storage is turned off.\n"));
    return;
  }
  s1 = get_user(&USERENTRY_INFO, u);
  if (s1 && s1[0] == '@')
    locked = 1;
  if (par[0] && strchr(CHANMETA, par[0])) {
    chname = newsplit(&par);
    if (!findchan_by_dname(chname)) {
      dprintf(idx, _("No such channel.\n"));
      return;
    }
    get_handle_chaninfo(dcc[idx].nick, chname, s);
    if (s[0] == '@')
      locked = 1;
    s1 = s;
  } else
    chname = 0;
  if (!par[0]) {
    if (s1 && s1[0] == '@')
      s1++;
    if (s1 && s1[0]) {
      if (chname) {
	dprintf(idx, "Info on %s: %s\n", chname, s1);
	dprintf(idx, _("Use '.info %s none' to remove it.\n"), chname);
      } else {
	dprintf(idx, _("Default info: %s\n"), s1);
	dprintf(idx, _("Use '.info none' to remove it.\n"));
      }
    } else
      dprintf(idx, _("No info has been set for you.\n"));
    putlog(LOG_CMDS, "*", "#%s# info %s", dcc[idx].nick, chname ? chname : "");
    return;
  }
  if (locked && !(u && (u->flags & USER_MASTER))) {
    dprintf(idx, _("Your info line is locked.  Sorry.\n"));
    return;
  }
  if (!strcasecmp(par, "none")) {
    if (chname) {
      par[0] = 0;
      set_handle_chaninfo(userlist, dcc[idx].nick, chname, NULL);
      dprintf(idx, _("Removed your info line on %s.\n"), chname);
      putlog(LOG_CMDS, "*", "#%s# info %s none", dcc[idx].nick, chname);
    } else {
      set_user(&USERENTRY_INFO, u, NULL);
      dprintf(idx, _("Removed your default info line.\n"));
      putlog(LOG_CMDS, "*", "#%s# info none", dcc[idx].nick);
    }
    return;
  }
/*  if (par[0] == '@')    This is stupid, and prevents a users info from being locked */
/*    par++;              without .tcl, or a tcl script, aka, 'half-assed' -poptix 4Jun01 */
  if (chname) {
    set_handle_chaninfo(userlist, dcc[idx].nick, chname, par);
    dprintf(idx, _("Your info on %1$s is now: %2$s\n"), chname, par);
    putlog(LOG_CMDS, "*", "#%s# info %s ...", dcc[idx].nick, chname);
  } else {
    set_user(&USERENTRY_INFO, u, par);
    dprintf(idx, _("Your default info is now: %s\n"), par);
    putlog(LOG_CMDS, "*", "#%s# info ...", dcc[idx].nick);
  }
}

static void cmd_chinfo(struct userrec *u, int idx, char *par)
{
  char *handle, *chname;
  struct userrec *u1;

  if (!use_info) {
    dprintf(idx, _("Info storage is turned off.\n"));
    return;
  }
  handle = newsplit(&par);
  if (!handle[0]) {
    dprintf(idx, "Usage: chinfo <handle> [channel] <new-info>\n");
    return;
  }
  u1 = get_user_by_handle(userlist, handle);
  if (!u1) {
    dprintf(idx, _("No such user.\n"));
    return;
  }
  if (par[0] && strchr(CHANMETA, par[0])) {
    chname = newsplit(&par);
    if (!findchan_by_dname(chname)) {
      dprintf(idx, _("No such channel.\n"));
      return;
    }
  } else
    chname = 0;
  if ((u1->flags & USER_BOT) && !(u->flags & USER_MASTER)) {
    dprintf(idx, _("You have to be master to change bots info.\n"));
    return;
  }
  if ((u1->flags & USER_OWNER) && !(u->flags & USER_OWNER)) {
    dprintf(idx, _("You can't change info for the bot owner.\n"));
    return;
  }
  if (chname) {
    get_user_flagrec(u, &user, chname);
    get_user_flagrec(u1, &victim, chname);
    if ((chan_owner(victim) || glob_owner(victim)) &&
	!(glob_owner(user) || chan_owner(user))) {
      dprintf(idx, _("You can't change info for the channel owner.\n"));
      return;
    }
  }
  putlog(LOG_CMDS, "*", "#%s# chinfo %s %s %s", dcc[idx].nick, handle,
	 chname ? chname : par, chname ? par : "");
  if (!strcasecmp(par, "none"))
    par[0] = 0;
  if (chname) {
    set_handle_chaninfo(userlist, handle, chname, par);
    if (par[0] == '@')
      dprintf(idx, _("New info (LOCKED) for %1$s on %2$s: %3$s\n"),
              handle, chname, &par[1]);
    else if (par[0])
      dprintf(idx, _("New info for %1$s on %2$s: %3$s\n"), handle, chname, par);
    else
      dprintf(idx, _("Wiped info for %1$s on %2$s\n"), handle, chname);
  } else {
    set_user(&USERENTRY_INFO, u1, par[0] ? par : NULL);
    if (par[0] == '@')
      dprintf(idx, _("New default info (LOCKED) for %1$s: %2$s\n"), handle,
             &par[1]);
    else if (par[0])
      dprintf(idx, _("New default info for %1$s: %2$s\n"), handle, par);
    else
      dprintf(idx, _("Wiped default info for %s\n"), handle);
  }
}

static void cmd_stick_yn(int idx, char *par, int yn)
{
  int i = 0, j;
  struct chanset_t *chan, *achan;
  char *stick_type, s[UHOSTLEN], chname[81];
  module_entry *me;

  stick_type = newsplit(&par);
  strlcpy(s, newsplit(&par), sizeof s);
  strlcpy(chname, newsplit(&par), sizeof chname);

  if (strcasecmp(stick_type, "exempt") &&
      strcasecmp(stick_type, "invite") &&
      strcasecmp(stick_type, "ban")) {
    strlcpy(chname, s, sizeof chname);
    strlcpy(s, stick_type, sizeof s);
  }
  if (!s[0]) {
    dprintf(idx, "Usage: %sstick [ban/exempt/invite] <hostmask or number> [channel]\n",
            yn ? "" : "un");
    return;
  }
  /* Now deal with exemptions */
  if (!strcasecmp(stick_type, "exempt")) {
    if (!use_exempts) {
      dprintf(idx,
              _("This command can only be used with use-exempts enabled.\n"));
      return;
    }
    if (!chname[0]) {
      i = u_setsticky_exempt(NULL, s,
                             (dcc[idx].user->flags & USER_MASTER) ? yn : -1);
      if (i > 0) {
        putlog(LOG_CMDS, "*", "#%s# %sstick exempt %s",
               dcc[idx].nick, yn ? "" : "un", s);
        dprintf(idx, "%s: %s\n", yn ? _("Stuck exempt") : _("Unstuck exempt"),
	        s);
        return;
      }
      strlcpy(chname, dcc[idx].u.chat->con_chan, sizeof chname);
    }
    /* Channel-specific exempt? */
    if (!(chan = findchan_by_dname(chname))) {
      dprintf(idx, _("No such channel.\n"));
      return;
    }
    if (i)
      snprintf(s, sizeof s, "%d", -i);
    j = u_setsticky_exempt(chan, s, yn);
    if (j > 0) {
      putlog(LOG_CMDS, "*", "#%s# %sstick exempt %s %s", dcc[idx].nick,
             yn ? "" : "un", s, chname);
      dprintf(idx, "%stuck %s exempt: %s\n", yn ? "S" : "Uns", chname, s);
      return;
    }
    dprintf(idx, "No such exempt.\n");
    return;
  /* Now the invites */
  } else if (!strcasecmp(stick_type, "invite")) {
    if (!use_invites) {
      dprintf(idx,
              _("This command can only be used with use-invites enabled.\n"));
      return;
    }
    if (!chname[0]) {
      i = u_setsticky_invite(NULL, s,
                             (dcc[idx].user->flags & USER_MASTER) ? yn : -1);
      if (i > 0) {
        putlog(LOG_CMDS, "*", "#%s# %sstick invite %s",
               dcc[idx].nick, yn ? "" : "un", s);
        dprintf(idx, "%stuck invite: %s\n", yn ? "S" : "Uns", s);
        return;
      }
      strlcpy(chname, dcc[idx].u.chat->con_chan, sizeof chname);
    }
    /* Channel-specific invite? */
    if (!(chan = findchan_by_dname(chname))) {
      dprintf(idx, _("No such channel.\n"));
      return;
    }
    if (i)
      snprintf(s, sizeof s, "%d", -i);
    j = u_setsticky_invite(chan, s, yn);
    if (j > 0) {
      putlog(LOG_CMDS, "*", "#%s# %sstick invite %s %s", dcc[idx].nick,
             yn ? "" : "un", s, chname);
      dprintf(idx, "%stuck %s invite: %s\n", yn ? "S" : "Uns", chname, s);
      return;
    }
    dprintf(idx, _("No such invite.\n"));
    return;
  }
  if (!chname[0]) {
    i = u_setsticky_ban(NULL, s,
                        (dcc[idx].user->flags & USER_MASTER) ? yn : -1);
    if (i > 0) {
      putlog(LOG_CMDS, "*", "#%s# %sstick ban %s",
             dcc[idx].nick, yn ? "" : "un", s);
      dprintf(idx, "%stuck ban: %s\n", yn ? "S" : "Uns", s);
      if ((me = module_find("irc", 0, 0)))
	for (achan = chanset; achan != NULL; achan = achan->next)
	  (me->funcs[IRC_CHECK_THIS_BAN])(achan, s, yn);
      return;
    }
    strlcpy(chname, dcc[idx].u.chat->con_chan, sizeof chname);
  }
  /* Channel-specific ban? */
  if (!(chan = findchan_by_dname(chname))) {
    dprintf(idx, _("No such channel.\n"));
    return;
  }
  if (i)
    snprintf(s, sizeof s, "%d", -i);
  j = u_setsticky_ban(chan, s, yn);
  if (j > 0) {
    putlog(LOG_CMDS, "*", "#%s# %sstick ban %s %s", dcc[idx].nick,
           yn ? "" : "un", s, chname);
    dprintf(idx, "%stuck %s ban: %s\n", yn ? "S" : "Uns", chname, s);
    if ((me = module_find("irc", 0, 0)))
      (me->funcs[IRC_CHECK_THIS_BAN])(chan, s, yn);
    return;
  }
  dprintf(idx, _("No such ban.\n"));
}


static void cmd_stick(struct userrec *u, int idx, char *par)
{
  cmd_stick_yn(idx, par, 1);
}

static void cmd_unstick(struct userrec *u, int idx, char *par)
{
  cmd_stick_yn(idx, par, 0);
}

static void cmd_pls_chrec(struct userrec *u, int idx, char *par)
{
  char *nick, *chn;
  struct chanset_t *chan;
  struct userrec *u1;
  struct chanuserrec *chanrec;

  if (!par[0]) {
    dprintf(idx, "Usage: +chrec <user> [channel]\n");
    return;
  }
  nick = newsplit(&par);
  u1 = get_user_by_handle(userlist, nick);
  if (!u1) {
    dprintf(idx, _("No such user.\n"));
    return;
  }
  if (!par[0])
    chan = findchan_by_dname(dcc[idx].u.chat->con_chan);
  else {
    chn = newsplit(&par);
    chan = findchan_by_dname(chn);
  }
  if (!chan) {
    dprintf(idx, _("No such channel.\n"));
    return;
  }
  get_user_flagrec(u, &user, chan->dname);
  get_user_flagrec(u1, &victim, chan->dname);
  if ((!glob_master(user) && !chan_master(user)) ||  /* drummer */
      (chan_owner(victim) && !chan_owner(user) && !glob_owner(user)) ||
      (glob_owner(victim) && !glob_owner(user))) {
    dprintf(idx, _("You have no permission to do that.\n"));
    return;
  }
  chanrec = get_chanrec(u1, chan->dname);
  if (chanrec) {
    dprintf(idx, _("User %1$s already has a channel record for %2$s.\n"),
	    nick, chan->dname);
    return;
  }
  putlog(LOG_CMDS, "*", "#%s# +chrec %s %s", dcc[idx].nick,
	 nick, chan->dname);
  add_chanrec(u1, chan->dname);
  dprintf(idx, "Added %1$s channel record for %2$s.\n", chan->dname, nick);
}

static void cmd_mns_chrec(struct userrec *u, int idx, char *par)
{
  char *nick, *chn = NULL;
  struct userrec *u1;
  struct chanuserrec *chanrec;

  if (!par[0]) {
    dprintf(idx, "Usage: -chrec <user> [channel]\n");
    return;
  }
  nick = newsplit(&par);
  u1 = get_user_by_handle(userlist, nick);
  if (!u1) {
    dprintf(idx, _("No such user.\n"));
    return;
  }
  if (!par[0]) {
    struct chanset_t *chan;

    chan = findchan_by_dname(dcc[idx].u.chat->con_chan);
    if (chan)
      chn = chan->dname;
    else {
      dprintf(idx, _("Invalid console channel.\n"));
      return;
    }
  } else
    chn = newsplit(&par);
  get_user_flagrec(u, &user, chn);
  get_user_flagrec(u1, &victim, chn);
  if ((!glob_master(user) && !chan_master(user)) ||  /* drummer */
      (chan_owner(victim) && !chan_owner(user) && !glob_owner(user)) ||
      (glob_owner(victim) && !glob_owner(user))) {
    dprintf(idx, _("You have no permission to do that.\n"));
    return;
  }
  chanrec = get_chanrec(u1, chn);
  if (!chanrec) {
    dprintf(idx, _("User %1$s doesn't have a channel record for %2$s.\n"),
            nick, chn);
    return;
  }
  putlog(LOG_CMDS, "*", "#%s# -chrec %s %s", dcc[idx].nick, nick, chn);
  del_chanrec(u1, chn);
  dprintf(idx, _("Removed %1$s channel record from %2$s.\n"), chn, nick);
}

static void cmd_pls_chan(struct userrec *u, int idx, char *par)
{
  char *chname;
  struct chanset_t *chan;

  if (!par[0]) {
    dprintf(idx, "Usage: +chan [%s]<channel> [options]\n", CHANMETA);
    return;
  }

  chname = newsplit(&par);
  if (findchan_by_dname(chname)) {
    dprintf(idx, _("That channel already exists!\n"));
    return;
  } else if ((chan = findchan(chname))) {
    dprintf(idx, _("That channel already exists as %s!\n"), chan->dname);
    return;
  } else if (strchr(CHANMETA, chname[0]) == NULL) {
    dprintf(idx, _("Invalid channel prefix.\n"));
    return;
  } else if (strchr(chname, ',') != NULL) {
    dprintf(idx, _("Invalid channel name.\n"));
    return;
  }

  if (tcl_channel_add(0, chname, par) == TCL_ERROR)
    dprintf(idx, _("Invalid channel or channel options.\n"));
  else
    putlog(LOG_CMDS, "*", "#%s# +chan %s", dcc[idx].nick, chname);
}

static void cmd_mns_chan(struct userrec *u, int idx, char *par)
{
  char *chname;
  struct chanset_t *chan;
  int i;

  if (!par[0]) {
    dprintf(idx, "Usage: -chan [%s]<channel>\n", CHANMETA);
    return;
  }
  chname = newsplit(&par);
  chan = findchan_by_dname(chname);
  if (!chan) {
    if ((chan = findchan(chname)))
      dprintf(idx,
              _("That channel exists with a short name of %s, use that.\n"),
              chan->dname);
    else
      dprintf(idx, _("That channel doesn't exist!\n"));
    return;
  }
  if (channel_static(chan)) {
    dprintf(idx, _("Cannot remove %s, it is not a dynamic channel!.\n"),
	    chname);
    return;
  }

  remove_channel(chan);
  dprintf(idx, _("Channel %s removed from the bot.\n"), chname);
  dprintf(idx, _("This includes any channel specific bans, invites, exemptions and user records that you set.\n"));
  putlog(LOG_CMDS, "*", "#%s# -chan %s", dcc[idx].nick, chname);
  for (i = 0; i < dcc_total; i++)
    if (dcc[i].type && (dcc[i].type->flags & DCT_CHAT) &&
	!irccmp(dcc[i].u.chat->con_chan, chan->dname)) {
      dprintf(i, _("%s is no longer a valid channel, changing your console to '*'\n"),
	      chname);
      strcpy(dcc[i].u.chat->con_chan, "*");
    }
}

static void cmd_chaninfo(struct userrec *u, int idx, char *par)
{
  char *chname, work[512];
  struct chanset_t *chan;
  int ii, tmp;
  struct udef_struct *ul;

  if (!par[0]) {
    chname = dcc[idx].u.chat->con_chan;
    if (chname[0] == '*') {
      dprintf(idx, _("Your console channel is invalid.\n"));
      return;
    }
  } else {
    chname = newsplit(&par);
    get_user_flagrec(u, &user, chname);
    if (!glob_master(user) && !chan_master(user)) {
      dprintf(idx, _("You don't have access to %s. \n"), chname);
      return;
    }
  }
  if (!(chan = findchan_by_dname(chname)))
    dprintf(idx, "No such channel defined.\n");
  else {
    dprintf(idx, "Settings for %s channel %s\n",
	    channel_static(chan) ? "static" : "dynamic", chan->dname);
    get_mode_protect(chan, work);
    dprintf(idx, "Protect modes (chanmode): %s\n", work[0] ? work : "None");
    dprintf(idx, "aop_delay: %d:%d\n", chan->aop_min, chan->aop_max);
    if (chan->ban_time)
      dprintf(idx, "ban_time: %d\n", chan->ban_time);
    else
      dprintf(idx, "ban_time: 0\n");
    if (chan->exempt_time)
      dprintf(idx, "exempt_time: %d\n", chan->exempt_time);
    else
      dprintf(idx, "exempt_time: 0\n");
    if (chan->invite_time)
      dprintf(idx, "invite_time: %d\n", chan->invite_time);
    else
      dprintf(idx, "invite_time: 0\n");

    dprintf(idx, "Other modes:\n");
    dprintf(idx, "     %cinactive       %cstatuslog      %csecret\n",
	    (chan->status & CHAN_INACTIVE) ? '+' : '-',
	    (chan->status & CHAN_LOGSTATUS) ? '+' : '-',
	    (chan->status & CHAN_SECRET) ? '+' : '-');
    dprintf(idx, "     %cgreet          %ccycle          %cdontkickops\n",
	    (chan->status & CHAN_GREET) ? '+' : '-',
	    (chan->status & CHAN_CYCLE) ? '+' : '-',
	    (chan->status & CHAN_DONTKICKOPS) ? '+' : '-');
    dprintf(idx, "     %cautovoice      %cnodesynch      %cenforcebans    %cdynamicbans\n",
	    (chan->status & CHAN_AUTOVOICE) ? '+' : '-',
	    (chan->status & CHAN_NODESYNCH) ? '+' : '-',
            (chan->status & CHAN_ENFORCEBANS) ? '+' : '-',
	    (chan->status & CHAN_DYNAMICBANS) ? '+' : '-');
    dprintf(idx, "     %cdynamicexempts                 %cdynamicinvites\n",
	    (chan->ircnet_status & CHAN_DYNAMICEXEMPTS) ? '+' : '-',
	    (chan->ircnet_status & CHAN_DYNAMICINVITES) ? '+' : '-');
    dprintf(idx, "     %chonor-global-bans              %chonor-global-exempts\n",
	    (chan->status & CHAN_HONORGLOBALBANS) ? '+' : '-',
	    (chan->ircnet_status & CHAN_HONORGLOBALEXEMPTS) ? '+' : '-');
    dprintf(idx, "     %chonor-global-invites           %cautoop\n",
	    (chan->ircnet_status & CHAN_HONORGLOBALINVITES) ? '+' : '-',
            (chan->status & CHAN_OPONJOIN) ? '+' : '-');

    ii = 1;
    tmp = 0;
    for (ul = udef; ul; ul = ul->next)
      if (ul->defined && ul->type == UDEF_FLAG) {
	int	work_len;

        if (!tmp) {
          dprintf(idx, "User defined channel flags:\n");
          tmp = 1;
        }
	if (ii == 1)
	  snprintf(work, sizeof work, "    ");
	work_len = strlen(work);
        snprintf(work + work_len, sizeof(work) - work_len, " %c%s",
		     getudef(ul->values, chan->dname) ? '+' : '-', ul->name);
        ii++;
        if (ii > 4) {
          dprintf(idx, "%s\n", work);
          ii = 1;
        }
      }
    if (ii > 1)
      dprintf(idx, "%s\n", work);

    work[0] = 0;
    ii = 1;
    tmp = 0;
    for (ul = udef; ul; ul = ul->next)
      if (ul->defined && ul->type == UDEF_INT) {
	int	work_len = strlen(work);

        if (!tmp) {
          dprintf(idx, "User defined channel settings:\n");
          tmp = 1;
        }
        snprintf(work + work_len, sizeof(work) - work_len, "%s: %d   ",
		     ul->name, getudef(ul->values, chan->dname));
        ii++;
        if (ii > 4) {
          dprintf(idx, "%s\n", work);
	  work[0] = 0;
          ii = 1;
        }
      }
    if (ii > 1)
      dprintf(idx, "%s\n", work);

	if (u->flags & USER_OWNER) {
		tmp = 0;
		for (ul = udef; ul; ul = ul->next)
			if (ul->defined && ul->type == UDEF_STR) {
				char *p = (char *)getudef(ul->values, chan->dname);
				if (!p) p = "{}";
				if (!tmp) {
					dprintf(idx, "User defined channel strings:\n");
					tmp = 1;
				}
				dprintf(idx, "%s: %s\n", ul->name, p);
			}
	}
    putlog(LOG_CMDS, "*", "#%s# chaninfo %s", dcc[idx].nick, chname);
  }
}

static void cmd_chanset(struct userrec *u, int idx, char *par)
{
  char *chname = NULL, answers[512], *parcpy;
  char *list[2], *bak, *buf;
  struct chanset_t *chan = NULL;
  int all = 0;

  if (!par[0])
    dprintf(idx, "Usage: chanset [%schannel] <settings>\n", CHANMETA);
  else {
    if (strlen(par) > 2 && par[0] == '*' && par[1] == ' ') {
      all = 1;
      get_user_flagrec(u, &user, chanset ? chanset->dname : "");
      if (!glob_master(user)) {
	dprintf(idx, _("You need to be a global master to use .chanset *.\n"));
	return;
      }
      newsplit(&par);
    } else {
      if (strchr(CHANMETA, par[0])) {
        chname = newsplit(&par);
        get_user_flagrec(u, &user, chname);
        if (!glob_master(user) && !chan_master(user)) {
	  dprintf(idx, _("You don't have access to %s. \n"), chname);
	  return;
	} else if (!(chan = findchan_by_dname(chname)) && (chname[0] != '+')) {
	  dprintf(idx, _("That channel doesn't exist!\n"));
	  return;
	}
	if (!chan) {
	  if (par[0])
	    *--par = ' ';
	  par = chname;
	}
      }
      if (!par[0] || par[0] == '*') {
        dprintf(idx, "Usage: chanset [%schannel] <settings>\n", CHANMETA);
        return;
      }
      if (!chan &&
          !(chan = findchan_by_dname(chname = dcc[idx].u.chat->con_chan))) {
        dprintf(idx, _("Invalid console channel.\n"));
        return;
      }
    }
    if (all)
      chan = chanset;
    bak = par;
    buf = malloc(strlen(par) + 1);
    while (chan) {
      chname = chan->dname;
      strcpy(buf, bak);
      par = buf;
      list[0] = newsplit(&par);
      answers[0] = 0;
      while (list[0][0]) {
	if (list[0][0] == '+' || list[0][0] == '-') {
	  if (tcl_channel_modify(0, chan, 1, list) == TCL_OK) {
	    strcat(answers, list[0]);
	    strcat(answers, " ");
	  } else if (!all || !chan->next)
	    dprintf(idx, "Error trying to set %s for %s, invalid mode\n",
		    list[0], all ? "all channels" : chname);
	  list[0] = newsplit(&par);
	  continue;
	}
	/* The rest have an unknown amount of args, so assume the rest of the
	 * line is args. 
	 */
	  list[1] = par;
	  /* Par gets modified in tcl_channel_modify under some
  	   * circumstances, so save it now.
	   */
	  parcpy = strdup(par);
          if (tcl_channel_modify(0, chan, 2, list) == TCL_OK) {
	    strcat(answers, list[0]);
	    strcat(answers, " { ");
	    strcat(answers, parcpy);
	    strcat(answers, " }");
	  } else if (!all || !chan->next)
	    dprintf(idx, "Error trying to set %s for %s, invalid option\n",
		    list[0], all ? "all channels" : chname);
          free(parcpy);
	break;
      }
      if (!all && answers[0]) {
	dprintf(idx, "Successfully set modes { %s } on %s.\n",
		answers, chname);
	putlog(LOG_CMDS, "*", "#%s# chanset %s %s", dcc[idx].nick, chname,
	       answers);
      }
      if (!all)
        chan = NULL;
      else
        chan = chan->next;
    }
    if (all && answers[0]) {
      dprintf(idx, "Successfully set modes { %s } on all channels.\n",
	      answers);
      putlog(LOG_CMDS, "*", "#%s# chanset * %s", dcc[idx].nick, answers);
    }
    free(buf);
  }
}

static void cmd_chansave(struct userrec *u, int idx, char *par)
{
  if (!chanfile[0])
    dprintf(idx, _("No channel saving file defined.\n"));
  else {
    dprintf(idx, _("Saving all dynamic channel settings.\n"));
    putlog(LOG_CMDS, "*", "#%s# chansave", dcc[idx].nick);
    write_channels();
  }
}

static void cmd_chanload(struct userrec *u, int idx, char *par)
{
  if (!chanfile[0])
    dprintf(idx, _("No channel saving file defined.\n"));
  else {
    dprintf(idx, _("Reloading all dynamic channel settings.\n"));
    putlog(LOG_CMDS, "*", "#%s# chanload", dcc[idx].nick);
    setstatic = 0;
    read_channels(1);
  }
}

/* DCC CHAT COMMANDS
 *
 * Function call should be:
 *    int cmd_whatever(idx,"parameters");
 *
 * NOTE: As with msg commands, the function is responsible for any logging.
 */
static cmd_t C_dcc_irc[] =
{
  {"+ban",	"o|o",	(Function) cmd_pls_ban,		NULL},
  {"+exempt",	"o|o",	(Function) cmd_pls_exempt,	NULL},
  {"+invite",	"o|o",	(Function) cmd_pls_invite,	NULL},
  {"+chan",	"n",	(Function) cmd_pls_chan,	NULL},
  {"+chrec",	"m|m",	(Function) cmd_pls_chrec,	NULL},
  {"-ban",	"o|o",	(Function) cmd_mns_ban,		NULL},
  {"-chan",	"n",	(Function) cmd_mns_chan,	NULL},
  {"-chrec",	"m|m",	(Function) cmd_mns_chrec,	NULL},
  {"bans",	"o|o",	(Function) cmd_bans,		NULL},
  {"-exempt",	"o|o",	(Function) cmd_mns_exempt,	NULL},
  {"-invite",	"o|o",	(Function) cmd_mns_invite,	NULL},
  {"exempts",	"o|o",	(Function) cmd_exempts,		NULL},
  {"invites",	"o|o",	(Function) cmd_invites,		NULL},
  {"chaninfo",	"m|m",	(Function) cmd_chaninfo,	NULL},
  {"chanload",	"n|n",	(Function) cmd_chanload,	NULL},
  {"chanset",	"n|n",	(Function) cmd_chanset,		NULL},
  {"chansave",	"n|n",	(Function) cmd_chansave,	NULL},
  {"chinfo",	"m|m",	(Function) cmd_chinfo,		NULL},
  {"info",	"",	(Function) cmd_info,		NULL},
  {"stick",	"o|o",	(Function) cmd_stick,		NULL},
  {"unstick",	"o|o",	(Function) cmd_unstick,		NULL},
  {NULL,	NULL,	NULL,				NULL}
};

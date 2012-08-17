/* core_config.c: config file
 *
 * Copyright (C) 2003, 2004 Eggheads Development Team
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

#ifndef lint
static const char rcsid[] = "$Id: core_config.c,v 1.24 2004/10/17 05:14:07 stdarg Exp $";
#endif

#include <eggdrop/eggdrop.h>
#include "core_config.h"

extern char *configfile;
core_config_t core_config = {0};
void *config_root = NULL;

static config_var_t core_config_vars[] = {
	/* General bot stuff. */
	{"botname", &core_config.botname, CONFIG_STRING},	/* DDC	*/
	{"userfile", &core_config.userfile, CONFIG_STRING},	/* DDC	*/
	{"lockfile", &core_config.lockfile, CONFIG_STRING},	/* DDC	*/

	/* The owner. */
	{"owner", &core_config.owner, CONFIG_STRING},		/* DDC	*/
	{"admin", &core_config.admin, CONFIG_STRING},		/* DDC	*/

	/* Paths. */
	{"help_path", &core_config.help_path, CONFIG_STRING},	/* DDD	*/
	{"temp_path", &core_config.temp_path, CONFIG_STRING},	/* DDD	*/
	{"text_path", &core_config.text_path, CONFIG_STRING},	/* DDD	*/
	{"module_path", &core_config.module_path, CONFIG_STRING},/* DDD	*/

	/* Whois. */
	{"whois_items", &core_config.whois_items, CONFIG_STRING},/* DDD	*/

	/* Logging. */
	{"logging.keep_all", &core_config.logging.keep_all, CONFIG_INT},
	{"logging.quick", &core_config.logging.quick, CONFIG_INT},
	{"logging.max_size", &core_config.logging.max_size, CONFIG_INT},
	{"logging.switch_at", &core_config.logging.switch_at, CONFIG_INT},
	{"logging.suffix", &core_config.logging.suffix, CONFIG_STRING},

	/* Other. */
	{"die_on_sigterm", &core_config.die_on_sigterm, CONFIG_INT},/* DDD*/
	{0}
};


int core_config_init(const char *fname)
{
	/* Set default vals. */
	memset(&core_config, 0, sizeof(core_config));

	/* Hook the owner variable into libeggdrop. */
	egg_setowner(&core_config.owner);

	config_root = config_load(fname);
	if (config_root == NULL) return -1;

	config_set_root("eggdrop", config_root);
	config_link_table(core_config_vars, config_root, "eggdrop", 0, NULL);
	if (!core_config.botname) core_config.botname = strdup("eggdrop");
	if (!core_config.userfile) core_config.userfile = strdup("users.xml");
	if (!core_config.lockfile) core_config.lockfile = strdup("lock");
	if (!core_config.help_path) core_config.help_path = strdup("help/");
	if (!core_config.logging.suffix) core_config.logging.suffix = strdup(".%d%b%Y");

	config_update_table(core_config_vars, config_root, "eggdrop", 0, NULL);

	return (0);
}

int core_config_save(void)
{
	config_update_table(core_config_vars, config_root, "eggdrop", 0, NULL);

	config_save("eggdrop", configfile);

	return (0);
}

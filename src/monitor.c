/*
 *
 * Copyright 2008 Karsten Keil <kkeil@suse.de>
 * Copyright 2010 Thomas Zimmermann <bugs@vdm-design.de>
 *
 * This is based on:
 * http://git.misdn.org/?p=mISDNuser.git;a=blob;f=tools/loghex.c
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * The full GNU General Public License is included in this distribution in the
 * file called LICENSE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>

#include <config.h>

#ifdef HAVE_LIBCURL
#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#endif

#include <glib.h>

#ifdef HAVE_DBUSGLIB
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#endif

#ifdef HAVE_SQLITE3
#include <sqlite3.h>
#endif

#include <mISDNif.h>
#define AF_COMPATIBILITY_FUNC
#include <compat_af_isdn.h>

#include <getopt.h>

static int writer(char *data, size_t size, size_t nmemb, GString *buffer) {
	int result = 0;
	if (buffer != NULL && data != NULL) {
		g_string_append(buffer, data);
		result = size * nmemb;
	}
	return result;
}

static int dch_echo=0;

static void usage(char *pname)
{
	fprintf(stderr,"Call with %s [options]\n",pname);
	fprintf(stderr,"\n");
	fprintf(stderr,"\n     Valid options are:\n");
	fprintf(stderr,"\n");
	fprintf(stderr,"  -?          Usage ; printout this information\n");
	fprintf(stderr,"  -c<n>       use card number n (default 1)\n");
	fprintf(stderr,"  -m <msn>    only show calls to MSN <msn>\n");
	fprintf(stderr,"  -l <file>   write logfile <file>\n");
	fprintf(stderr,"  -w <file>   write wiresharkdump <file>\n");
#ifdef HAVE_SQLITE3
	fprintf(stderr,"  -d <file>   use number cache database <file>\n");
#endif
#ifdef HAVE_LIBCURL
	fprintf(stderr,"  -u <url>    append the number to <url> and show\n"); 
	fprintf(stderr,"              the result instead of the number only\n");
#endif
	fprintf(stderr,"\n");
}


static void write_esc (FILE *file, unsigned char *buf, int len)
{
    int i, byte;

    for (i = 0; i < len; ++i) {
		byte = buf[i];
		if (byte == 0xff || byte == 0xfe) {
			fputc(0xfe, file);
			byte -= 2;
		}
		fputc(byte, file);
	}

	if (ferror(file)) {
		fprintf(stderr, "Error on writing to file!\nAborting...");
		exit(1);
	}
}

static void write_wfile(FILE *f, unsigned char *buf, int len,
			struct timeval *tv, int protocol)
{
	struct mISDNhead	*hh = (struct mISDNhead *)buf;
	u_char			head[12], origin;

	/* skip PH_DATA_REQ if PH_DATA_E_IND are expected */
	if (dch_echo && (hh->prim == PH_DATA_REQ))
		return;

	if ((hh->prim != PH_DATA_REQ) && (hh->prim != PH_DATA_IND) &&
		    (hh->prim != PH_DATA_E_IND))
		return;
	if (protocol == ISDN_P_NT_S0 || protocol == ISDN_P_NT_E1)
		origin = hh->prim == PH_DATA_REQ ? 0 : 1;
	else
		origin = ((hh->prim == PH_DATA_REQ) ||
				(hh->prim == PH_DATA_E_IND)) ? 1 : 0;

	len -= MISDN_HEADER_LEN;

	fputc(0xff, f);

	head[0] = (unsigned char)(0xff & (tv->tv_usec >> 16));
	head[1] = (unsigned char)(0xff & (tv->tv_usec >> 8));
	head[2] = (unsigned char)(0xff & tv->tv_usec);
	head[3] = (unsigned char)0;
	head[4] = (unsigned char)(0xff & (tv->tv_sec >> 24));
	head[5] = (unsigned char)(0xff & (tv->tv_sec >> 16));
	head[6] = (unsigned char)(0xff & (tv->tv_sec >> 8));
	head[7] = (unsigned char)(0xff & tv->tv_sec);
	head[8] = (unsigned char) 0;
	head[9] = (unsigned char) origin;
	head[10]= (unsigned char)(0xff & (len >> 8));
	head[11]= (unsigned char)(0xff & len);

	write_esc(f, head, 12);
	write_esc(f, &buf[MISDN_HEADER_LEN], len);
	fflush(f);
}

static void write_lfile(FILE *f, unsigned char *p, int len)
{
	if (len>23) {
		char line[500], buffer[len];
		char *anfang, *ende;
		int i, x = 1;
		char n[] = "0";
		time_t lt;
		struct tm	*mt;

		anfang = strchr((char*)p, '!');
		ende = strchr((char*)p, 'p');
		if (anfang!=NULL) {
			buffer[0] = n[0];
			for(i = 2; i < (len-1); i++) {
				if (ende[0] == anfang[i]) break;
				buffer[x++] = anfang[i];
			}
			buffer[x] = '\0';

			lt = time(NULL);
			mt = localtime(&lt);
			sprintf(line, "%02d.%02d.%04d %02d:%02d:%02d : %s \r\n",
				mt->tm_mday, mt->tm_mon + 1, mt->tm_year + 1900,
				mt->tm_hour, mt->tm_min, mt->tm_sec, buffer);
			fputs(line, f);
			fflush(f);
		}
	}

}

static void printhex(unsigned char *p, int len)
{
	int	i;

	for (i = 1; i <= len; i++) {
		printf(" %02x", *p++);
		if ((i!=len) && !(i % 16))
			printf("\n                                 ");
	}
	printf("\n");
}

static char *getcallerid(unsigned char *p)
{
	char *anfang = NULL, *buffer = NULL;
	int i, numlen, x = 0;

	anfang = strchr((char*)p, 0x6c); /* Find Information element */

	if (anfang != NULL) {
		numlen = (anfang[1] - 2); /* get number length without 0 */
		buffer = (char*)malloc(sizeof(char) * (numlen + 2));
		if (anfang[2] & 0x20) /* check Number type = national number */
			buffer[x++] = '0'; /* add leading 0 */
		else if (anfang[2] & 0x10)
			/* check Number type = international number */
			buffer[x++] = '+'; /* add leading + */
		anfang += 4; /* go to number start */
		for (i = 0; i < numlen; i++)
			buffer[x++] = anfang[i];
		buffer[x] = '\0';
	}

	return buffer;
}

static char *getmsn(unsigned char *p)
{
	char *anfang = NULL, *buffer = NULL;
	int i, numlen, x = 0;

	anfang = strchr((char*)p, 0x70); /* Find Information element */

	if (anfang != NULL) {
		numlen = (anfang[1] - 1); /* get number length without 0 */
		anfang += 3; /* go to number start */
		buffer = (char*)malloc(sizeof(char) * (numlen + 1));
		for(i = 0; i < numlen; i++)
			buffer[x++] = anfang[i];
		buffer[x] = '\0';
	}

	return buffer;
}

static char *getcallerinfo(char *number, const char *url)
{
	GString *text, *chunk, *url2;

	chunk = g_string_new("");
#ifdef HAVE_LIBCURL
	if (url != NULL) {
		url2 = g_string_new(url);
		g_string_append(url2, number);

		CURL *curl_handle;
		curl_global_init(CURL_GLOBAL_ALL);
		curl_handle = curl_easy_init();
		curl_easy_setopt(curl_handle, CURLOPT_URL,
				 g_string_free(url2, FALSE));
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, writer);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, chunk);
		curl_easy_setopt(curl_handle, CURLOPT_USERAGENT,
				 "libcurl-agent/1.0");
		curl_easy_perform(curl_handle);
		curl_easy_cleanup(curl_handle);
		curl_global_cleanup();
	}
#endif

	if (chunk->len > 10) {
		text = chunk;
	} else {
		g_string_free(chunk, TRUE);
		text = g_string_new("<br>");
		g_string_append(text, number);
		g_string_append(text, "<br>");
	}
	
	return g_string_free(text, FALSE);
}

static void shownotification(char *text)
{
#ifdef HAVE_DBUSGLIB
/*
	<method name="Notify">
		<arg name="app_name" type="s" direction="in"/>
		<arg name="id" type="u" direction="in"/>
		<arg name="icon" type="s" direction="in"/>
		<arg name="summary" type="s" direction="in"/>
		<arg name="body" type="s" direction="in"/>
		<arg name="actions" type="as" direction="in"/>
		<arg name="hints" type="a{sv}" direction="in"/>
		<arg name="timeout" type="i" direction="in"/>
		<arg name="return_id" type="u" direction="out"/>
	</method>
*/
	DBusGConnection* dbus_conn;
	DBusGProxy *dbus_proxy;

	dbus_conn = dbus_g_bus_get(DBUS_BUS_SESSION, NULL);
	dbus_proxy = dbus_g_proxy_new_for_name(dbus_conn,
					"org.freedesktop.Notifications",
					"/org/freedesktop/Notifications",
					"org.freedesktop.Notifications");

	if (dbus_proxy != NULL) {
		GArray *actions = g_array_sized_new(TRUE, FALSE, 
						    sizeof(gchar *), 0);
		GHashTable *hints = g_hash_table_new_full(g_str_hash,
						g_str_equal, g_free, g_free);

		dbus_g_proxy_call_no_reply(dbus_proxy, "Notify",
					G_TYPE_STRING, PACKAGE,
					G_TYPE_UINT, 0,
					G_TYPE_STRING, "quassel",
					G_TYPE_STRING, "Eingehender Anruf",
					G_TYPE_STRING, text,
					G_TYPE_STRV,
					(gchar **)g_array_free(actions, FALSE),
					dbus_g_type_get_map("GHashTable",
							    G_TYPE_STRING,
							    G_TYPE_VALUE),
					   hints,
					G_TYPE_INT, -1,
					G_TYPE_INVALID);

		g_hash_table_destroy(hints);
	}
	g_object_unref(dbus_proxy);
	dbus_g_connection_unref(dbus_conn);
#endif
}

static char *checkcallerinfo(char *number, const char *sqlitedb)
{
#ifdef HAVE_SQLITE3
	if (strlen(sqlitedb)) {
		int retval;
		sqlite3_stmt *stmt;
		sqlite3 *handle;
		char *text = NULL;
		retval = sqlite3_open(sqlitedb, &handle);
		if(retval) {
			printf("Database connection failed\n");
			return NULL;
		}
		retval = sqlite3_prepare_v2(handle,"SELECT notification FROM numbercache WHERE number=?;",-1,&stmt,0);
		if(retval) {
			printf("Selecting data from DB Failed\n");
			sqlite3_finalize(stmt);
			sqlite3_close(handle);
			return NULL;
		}
		sqlite3_bind_text(stmt, 1, number, strlen(number), NULL);
        
		while(1) {
			retval = sqlite3_step(stmt);
        
			if(retval == SQLITE_ROW) {
				const unsigned char *tmp = 
					(const unsigned char*)
					sqlite3_column_text(stmt,0);
				text = (char *)malloc(sizeof(char) *
					(strlen((const char *)tmp)+1));
				sprintf(text, "%s", tmp);
				printf("Found in Database: %s : %s\n", number,
				       text);
			}
			else if(retval == SQLITE_DONE) {
				break;
			}
			else {
				printf("Some error encountered while reading");
				printf(" number cache\n");
				return NULL;
			}
		}

		sqlite3_finalize(stmt);
		sqlite3_close(handle);

		return text;
	}
	else
#endif
		(void)number;
		(void)sqlitedb;
		return NULL;
}

static void storecallerinfo(char *number, char *text, const char *sqlitedb)
{
#ifdef HAVE_SQLITE3
	if (strlen(sqlitedb)) {
		int retval;
		sqlite3 *handle;
		retval = sqlite3_open(sqlitedb, &handle);
		if(retval) {
			printf("Database connection failed\n");
			return;
		}		
		char *query = 
			sqlite3_mprintf("INSERT INTO numbercache VALUES(%Q,%Q)",
					number, text);
		sqlite3_exec(handle, query, 0, 0, 0);
		sqlite3_free(query);
		printf("%s not found in database: inserting\n", number);
		sqlite3_close(handle);
	}
#endif
	(void)number;
	(void)text;
	(void)sqlitedb;
}

static void notify(unsigned char *p, int len, const char *url,
		   const char *checkmsn, const char *sqlitedb)
{
	if (len > 6 && p[6] == 0x05) { /* only if it's a call setup */
		char *number, *text, *msn, *notify;

		number = getcallerid(p);
		msn = getmsn(p);

		if (msn != NULL && checkmsn != NULL &&
			0 == strcmp(msn, checkmsn)) {
			printf("This call is not for %s, it's for: %s",
			       checkmsn, msn);
			free(msn);
			free(number);
			return;
		}

		if (number != NULL) {
			text = checkcallerinfo(number, sqlitedb);

			if (text == NULL) {
				text = getcallerinfo(number, url);
				storecallerinfo(number, text, sqlitedb);
			}

			notify = malloc(sizeof(char) *
					(strlen(text) + strlen(msn) + 50));

			if (msn) {
				sprintf(notify, "%s<br>Called MSN: %s", text,
					msn);
				free(msn);
			}
			else 
				sprintf(notify, "%s", text);

			shownotification(notify);

			free(number);
			free(notify);
			free(text);
		}
	}
}

struct ctstamp {
	size_t		cmsg_len;
	int		cmsg_level;
	int		cmsg_type;
	struct timeval	tv;
};

int main(int argc, char *argv[])
{
	int i, channel, cardnr = 0, log_socket = 0, buflen = 512;
	int result, opt, c;
	u_int cnt;
	struct sockaddr_mISDN  log_addr;
	char *wfilename = NULL, *lfilename = NULL, *url = NULL;
	char *sqlitedb = NULL, *msn = NULL;
	u_char buffer[buflen];
	struct msghdr mh;
	struct iovec iov[1];
	struct ctstamp cts;
	struct tm *mt;
	struct mISDN_devinfo di;
	struct mISDNhead *hh;
	struct mISDNversion ver;
	FILE *wfile = NULL, *lfile = NULL;

	/* Initialise di with 0 */
	di.id = 0;
	di.Dprotocols = 0;
	di.Bprotocols = 0;
	di.protocol = 0;
	di.nrbchan = 0;
	for (i = 0; i < MISDN_MAX_IDLEN; i++) di.name[i] = '\0';
	for (i = 0; i < MISDN_CHMAP_SIZE; i++) di.channelmap[i] = (u_char)'\0';

	g_type_init();

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{0, 0, 0, 0}
		};

		c = getopt_long (argc, argv, "c:m:w:l:u:d:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'c':
				cardnr=atol(optarg);
				break;
			case 'm':
				msn = (char *)malloc(sizeof(char) * (strlen(optarg)+1));
				if (msn == NULL) {
					fprintf(stderr," -m filename too long: Out of memory!\n");
					exit(1);
				}
				strcpy(msn, optarg);
				break;
			case 'w':
				wfilename = (char *)malloc(sizeof(char) * (strlen(optarg)+1));
				if (wfilename == NULL) {
					fprintf(stderr," -w filename too long: Out of memory!\n");
					exit(1);
				}
				strcpy(wfilename, optarg);
				break;
			case 'l':
				lfilename = (char *)malloc(sizeof(char) * (strlen(optarg)+1));
				if (lfilename == NULL) {
					fprintf(stderr," -l filename too long: Out of memory!\n");
					exit(1);
				}
				strcpy(lfilename, optarg);
				break;
			case 'u':
				url = (char *)malloc(sizeof(char) * (strlen(optarg)+1));
				if (url == NULL) {
					fprintf(stderr," -u URL too long: Out of memory!\n");
					exit(1);
				}
				strcpy(url, optarg);
				break;
			case 'd':
				sqlitedb = (char *)malloc(sizeof(char) * (strlen(optarg)+1));
				if (sqlitedb == NULL) {
					fprintf(stderr," -d filename too long: Out of memory!\n");
					exit(1);
				}
				strcpy(sqlitedb, optarg);
				break;
			case '?' :
				usage(argv[0]);
				exit(1);
				break;
			default  :
				fprintf(stderr,"Unknown Switch %c\n",c);
				usage(argv[0]);
				exit(1);
				break;
		}
	}

	if (cardnr < 0) {
		fprintf(stderr,"card nr may not be negative\n");
		exit(1);
	}

	init_af_isdn();

	if ((log_socket = socket(PF_ISDN, SOCK_RAW, 0)) < 0) {
		printf("could not open socket %s\n", strerror(errno));
		exit(1);
	}

	result = ioctl(log_socket, IMGETVERSION, &ver);
	if (result < 0) {
		printf("ioctl error %s\n", strerror(errno));
		exit(1);
	}
	printf("mISDN kernel version %d.%02d.%d found\n", ver.major, ver.minor,
	       ver.release);
	printf("mISDN user   version %d.%02d.%d found\n", MISDN_MAJOR_VERSION,
	       MISDN_MINOR_VERSION, MISDN_RELEASE);

	if (ver.major != MISDN_MAJOR_VERSION) {
		printf("VERSION incompatible please update\n");
		exit(1);
	}

	result = ioctl(log_socket, IMGETCOUNT, &cnt);
	if (result < 0) {
		printf("ioctl error %s\n", strerror(errno));
		exit(1);
	} else
		printf("%d controller%s found\n", cnt, (cnt==1)?"":"s");

	di.id = cardnr;
	result = ioctl(log_socket, IMGETDEVINFO, &di);
	if (result < 0) {
		printf("ioctl error %s\n", strerror(errno));
	} else {
		printf("	id:		%d\n", di.id);
		printf("	Dprotocols:	%08x\n", di.Dprotocols);
		printf("	Bprotocols:	%08x\n", di.Bprotocols);
		printf("	protocol:	%d\n", di.protocol);
		printf("	channelmap:	");
		for (i = MISDN_CHMAP_SIZE - 1; i >= 0; i--)
			printf("%02x", di.channelmap[i]);
		printf("\n");
		printf("	nrbchan:	%d\n", di.nrbchan);
		printf("	name:		%s\n", di.name);
	}

	close(log_socket);

	if (di.protocol == ISDN_P_NONE) /* default TE */
		di.protocol = ISDN_P_TE_S0;

	if ((log_socket = socket(PF_ISDN, SOCK_DGRAM, di.protocol)) < 0) {
		printf("could not open log socket %s\n", strerror(errno));
		exit(1);
	}

	log_addr.family = AF_ISDN;
	log_addr.dev = cardnr;

	/* try to bind on D/E channel first, fallback to D channel on error */
	result = -1;
	channel = 1;
	
	while ((result < 0) && (channel >= 0)) {
		log_addr.channel = (unsigned char)channel;
		result = bind(log_socket, (struct sockaddr *) &log_addr,
			sizeof(log_addr));
		printf("log bind ch(%i) return %d\n", log_addr.channel, result);
		if (result < 0) {
			printf("log bind error %s\n", strerror(errno));
			close(log_socket);
			if (channel == 0) {
				exit(1);
			}
			channel--;
			if ((log_socket = 
				socket(PF_ISDN, SOCK_DGRAM, di.protocol)) < 0) {
				printf("could not open log socket %s\n",
				       strerror(errno));
				exit(1);
			}
		}
	}
	dch_echo = (log_addr.channel == 1);

	opt = 1;
	result = setsockopt(log_socket, SOL_MISDN, MISDN_TIME_STAMP, &opt,
			    sizeof(opt));
	if (result < 0) {
		printf("log  setsockopt error %s\n", strerror(errno));
	}

	if (strlen(wfilename)) {
		wfile = fopen(wfilename, "w");
		if (wfile) {
			fprintf(wfile, "EyeSDN");
			fflush(wfile);
		} else
			printf("cannot open wireshark dump file(%s)\n",
			       wfilename);
	}

	if (strlen(lfilename)) {
		lfile = fopen(lfilename, "a");
		if (lfile) {
			fprintf(lfile, "\nmisdn_monitor started\n");
			fflush(lfile);
		} else
			printf("cannot open log file(%s)\n",
			       lfilename);
	}
#ifdef HAVE_SQLITE3
	if (strlen(sqlitedb)) {
		int retval;
		sqlite3 *handle;
		retval = sqlite3_open(sqlitedb, &handle);
		if(retval) {
			printf("Database connection failed\n");
			exit(1);
		}
		char create_table[100] = "CREATE TABLE IF NOT EXISTS numbercache (number TEXT PRIMARY KEY, notification TEXT NOT NULL)";
		retval = sqlite3_exec(handle,create_table,0,0,0);
		sqlite3_close(handle);
	}
#endif
	hh = (struct mISDNhead *)buffer;

	while (1) {
		mh.msg_name = NULL;
		mh.msg_namelen = 0;
		mh.msg_iov = iov;
		mh.msg_iovlen = 1;
		mh.msg_control = &cts;
		mh.msg_controllen = sizeof(cts);
		mh.msg_flags = 0;
		iov[0].iov_base = buffer;
		iov[0].iov_len = buflen;
		result = recvmsg(log_socket, &mh, 0);
		if (result < 0) {
			printf("read error %s\n", strerror(errno));
			break;
		} else {
			if (mh.msg_flags) {
				printf("received message with msg_flags(%x)\n",
				       mh.msg_flags);
			}
			if (cts.cmsg_type == MISDN_TIME_STAMP) {
				mt = localtime((time_t *)&cts.tv.tv_sec);
				printf("%02d.%02d.%04d %02d:%02d:%02d.%06ld",
				       mt->tm_mday, mt->tm_mon + 1,
				       mt->tm_year + 1900, mt->tm_hour,
				       mt->tm_min, mt->tm_sec, cts.tv.tv_usec);
			} else {
				cts.tv.tv_sec = 0;
				cts.tv.tv_usec = 0;
			}
			printf(" received %3d bytes prim = %04x id=%08x",
				result, hh->prim, hh->id);
			if ((unsigned)result > MISDN_HEADER_LEN) {
				if (wfile) write_wfile(wfile, buffer, result,
					&cts.tv, di.protocol);
				if (lfile) write_lfile(lfile,
					&buffer[MISDN_HEADER_LEN],
					result - MISDN_HEADER_LEN);
				printhex(&buffer[MISDN_HEADER_LEN],
					 result - MISDN_HEADER_LEN);
				notify(&buffer[MISDN_HEADER_LEN],
				       result - MISDN_HEADER_LEN,
				       url, msn, sqlitedb);
			} else
				printf("\n");
		}
	}
	close(log_socket);
	if (wfile)
		fclose(wfile);
	if (lfile)
		fclose(lfile);
	return (0);
}

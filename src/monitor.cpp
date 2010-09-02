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
#include <iostream>
#include <cstring>
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

#ifdef HAVE_DBUSGLIB
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#endif

#include <mISDNif.h>
#define AF_COMPATIBILITY_FUNC
#include <compat_af_isdn.h>

// This is the writer call back function used by curl
static int writer(char *data, size_t size, size_t nmemb,
                  std::string *buffer)
{
  // What we will return
  int result = 0;

  // Is there anything in the buffer?
  if (buffer != NULL)
  {
    // Append the data to the buffer
    buffer->append(data, size * nmemb);

    // How much did we write?
    result = size * nmemb;
  }

  return result;
} 

static int dch_echo=0;

static void 
usage(char *pname)
{
	fprintf(stderr,"Call with %s [options]\n",pname);
	fprintf(stderr,"\n");
	fprintf(stderr,"\n     Valid options are:\n");
	fprintf(stderr,"\n");
	fprintf(stderr,"  -?          Usage ; printout this information\n");
	fprintf(stderr,"  -c<n>       use card number n (default 1)\n");
	fprintf(stderr,"  -l <file>   write logfile <file>\n");
	fprintf(stderr,"  -w <file>   write wiresharkdump <file>\n");
	fprintf(stderr,"  -u <url>    Appends the number to <url> and shows\n"); 
	fprintf(stderr,"              the result instead of the number only\n");
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

static void write_wfile(FILE *f, unsigned char *buf, int len, struct timeval *tv, int protocol)
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

static void write_lfile(FILE *f, unsigned char *p, int len) {
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
			sprintf(line, "%02d.%02d.%04d %02d:%02d:%02d : %s \r\n", mt->tm_mday, mt->tm_mon + 1,
				mt->tm_year + 1900, mt->tm_hour, mt->tm_min, mt->tm_sec, buffer);
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

static void notify(unsigned char *p, int len, char url)
{
	if (len>23) {
		char url2[strlen(url)+len], buffer[len];
		char *anfang, *ende, *text;
		int i, x = 1;
		char n[] = "0";
		std::string chunk;

		anfang = strchr((char*)p, '!');
		ende = strchr((char*)p, 'p');
		if (anfang!=NULL) {
		
			buffer[0] = n[0];
			for(i = 2; i < (len-1); i++) {
				if (ende[0] == anfang[i]) break;
				buffer[x++] = anfang[i];
			}
			buffer[x] = '\0';
			sprintf(text, "<br>", buffer, "<br>");

#ifdef HAVE_LIBCURL
			sprintf(url2, "%s%s", url, buffer);
			CURL *curl_handle;
			curl_global_init(CURL_GLOBAL_ALL);
			curl_handle = curl_easy_init();
			curl_easy_setopt(curl_handle, CURLOPT_URL, url);
			curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, writer);
			curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &chunk);
			curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
			curl_easy_perform(curl_handle);
			curl_easy_cleanup(curl_handle);
			curl_global_cleanup();

			if (chunk.length()>10)
				 sprintf(text, chunk.c_str());	
#endif

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
			GArray *actions = g_array_sized_new(TRUE, FALSE, sizeof(gchar *), 0);
			GHashTable *hints = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

			dbus_conn = dbus_g_bus_get(DBUS_BUS_SESSION, NULL);
			dbus_proxy = dbus_g_proxy_new_for_name(dbus_conn, "org.freedesktop.Notifications",
								"/org/freedesktop/Notifications",
								"org.freedesktop.Notifications");

			dbus_g_proxy_call_no_reply(dbus_proxy, "Notify",
						   G_TYPE_STRING, PACKAGE,
						   G_TYPE_UINT, 0,
						   G_TYPE_STRING, "quassel",
						   G_TYPE_STRING, "Eingehender Anruf",
						   G_TYPE_STRING, text,
						   G_TYPE_STRV, (gchar **)g_array_free(actions, FALSE),
						   dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE), hints,
						   G_TYPE_INT, -1,
						   G_TYPE_INVALID);

			g_hash_table_destroy(hints);
			g_object_unref(dbus_proxy);
			dbus_g_connection_unref(dbus_conn);
#endif
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

int
main(int argc, char *argv[])
{
	int	aidx=1, idx, i, channel;
	int	cardnr = 0;
	int	log_socket;
	struct sockaddr_mISDN  log_addr;
	int	buflen = 512;
	char	sw;
	char	wfilename[512], lfilename[512], url[512];
	u_char	buffer[buflen];
	struct msghdr	mh;
	struct iovec	iov[1];
	struct ctstamp	cts;
	struct tm	*mt;
	int	result;
	int	opt;
	u_int	cnt;
	struct mISDN_devinfo	di;
	struct mISDNhead 	*hh;
	struct mISDNversion	ver;
	FILE	*wfile = NULL, *lfile = NULL;
	
	*wfilename = 0;
	while (aidx < argc) {
		if (argv[aidx] && argv[aidx][0]=='-') {
			sw=argv[aidx][1];
			switch (sw) {
				case 'c':
					if (argv[aidx][2]) {
						cardnr=atol(&argv[aidx][2]);
					}
					break;
				case 'w':
					if (!argv[aidx][2]) {
						idx = 0;
						aidx++;
					} else {
						idx=2;
					}
					if (aidx<=argc) {
						if (512 <= strlen(&argv[aidx][idx])) {
							fprintf(stderr," -w filename too long\n");
							exit(1);
						}
						strcpy(wfilename, &argv[aidx][idx]);
					} else {
						fprintf(stderr," Switch %c without value\n",sw);
						exit(1);
					}
					break;
				case 'l':
					if (!argv[aidx][2]) {
						idx = 0;
						aidx++;
					} else {
						idx=2;
					}
					if (aidx<=argc) {
						if (512 <= strlen(&argv[aidx][idx])) {
							fprintf(stderr," -l filename too long\n");
							exit(1);
						}
						strcpy(lfilename, &argv[aidx][idx]);
					} else {
						fprintf(stderr," Switch %c without value\n",sw);
						exit(1);
					}
					break;
				case 'u':
					if (!argv[aidx][2]) {
						idx = 0;
						aidx++;
					} else {
						idx=2;
					}
					if (aidx<=argc) {
						if (512 <= strlen(&argv[aidx][idx])) {
							fprintf(stderr," -u URL too long\n");
							exit(1);
						}
						strcpy(url, &argv[aidx][idx]);
					} else {
						fprintf(stderr," Switch %c without value\n",sw);
						exit(1);
					}
					break;
				case '?' :
					usage(argv[0]);
					exit(1);
					break;
				default  : fprintf(stderr,"Unknown Switch %c\n",sw);
					usage(argv[0]);
					exit(1);
					break;
			}
		}  else {
			fprintf(stderr,"Undefined argument %s\n",argv[aidx]);
			usage(argv[0]);
			exit(1);
		}
		aidx++;
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
	printf("mISDN kernel version %d.%02d.%d found\n", ver.major, ver.minor, ver.release);
	printf("mISDN user   version %d.%02d.%d found\n", MISDN_MAJOR_VERSION, MISDN_MINOR_VERSION, MISDN_RELEASE);

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
			if ((log_socket = socket(PF_ISDN, SOCK_DGRAM, di.protocol)) < 0) {
				printf("could not open log socket %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	dch_echo = (log_addr.channel == 1);

	opt = 1;
	result = setsockopt(log_socket, SOL_MISDN, MISDN_TIME_STAMP, &opt, sizeof(opt));
	if (result < 0) {
		printf("log  setsockopt error %s\n", strerror(errno));
	}

	if (strlen(wfilename)) {
		wfile = fopen(wfilename, "w");
		if (wfile) {
			fprintf(wfile, "EyeSDN");
			fflush(wfile);
		} else
			printf("cannot open wireshark dump file(%s)\n", wfilename);
	}

	if (strlen(lfilename)) {
		lfile = fopen(lfilename, "a");
		if (lfile) {
			fprintf(lfile, "misdn_monitor started\n\n");
			fflush(lfile);
		} else
			printf("cannot open wireshark dump file(%s)\n", lfilename);
	}

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
				printf("received message with msg_flags(%x)\n", mh.msg_flags);
			}
			if (cts.cmsg_type == MISDN_TIME_STAMP) {
				mt = localtime((time_t *)&cts.tv.tv_sec);
				printf("%02d.%02d.%04d %02d:%02d:%02d.%06ld", mt->tm_mday, mt->tm_mon + 1, mt->tm_year + 1900,
					mt->tm_hour, mt->tm_min, mt->tm_sec, cts.tv.tv_usec);
			} else {
				cts.tv.tv_sec = 0;
				cts.tv.tv_usec = 0;
			}
			if (wfile && (static_cast<unsigned int>(result) > MISDN_HEADER_LEN))
				write_wfile(wfile, buffer, result, &cts.tv, di.protocol);
			if (lfile && (static_cast<unsigned int>(result) > MISDN_HEADER_LEN))
				write_lfile(lfile, &buffer[MISDN_HEADER_LEN], result - MISDN_HEADER_LEN);
			printf(" received %3d bytes prim = %04x id=%08x",
				result, hh->prim, hh->id);
			if (static_cast<unsigned int>(result) > MISDN_HEADER_LEN) {
				printhex(&buffer[MISDN_HEADER_LEN], result - MISDN_HEADER_LEN);
				notify(&buffer[MISDN_HEADER_LEN], result - MISDN_HEADER_LEN, url);
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

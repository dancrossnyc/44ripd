#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>

#include "log.h"

void
initlog(void)
{
	openlog("44ripd", LOG_CONS | LOG_PERROR | LOG_PID, LOG_LOCAL0);
}

void
debug(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_DEBUG, fmt, ap);
	va_end(ap);
}

void
info(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_INFO, fmt, ap);
	va_end(ap);
}

void
notice(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_NOTICE, fmt, ap);
	va_end(ap);
}

void
error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_WARNING, fmt, ap);
	va_end(ap);
}

void
fatal(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

void
fatale(const char *msg)
{
	syslog(LOG_ERR, "%s: %m", msg);
	exit(EXIT_FAILURE);
}

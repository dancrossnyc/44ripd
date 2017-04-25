#ifndef RIPD_LOG_H
#define RIPD_LOG_H

void initlog(void);
void debug(const char *restrict fmt, ...);
void info(const char *restrict fmt, ...);
void notice(const char *restrict fmt, ...);
void error(const char *restrict fmt, ...);
void fatal(const char *restrict fmt, ...);
void fatal_err(const char *restrict msg);

#endif

NAME = timedatex

CFLAGS = -O2 -Wall -g
CPPFLAGS := $(shell pkg-config --cflags glib-2.0 gio-2.0)
LDFLAGS := $(shell pkg-config --libs glib-2.0 gio-2.0)

ifeq ($(shell pkg-config libselinux || echo no),)
CPPFLAGS += $(shell pkg-config --cflags libselinux) -DHAVE_SELINUX
LDFLAGS += $(shell pkg-config --libs libselinux)
endif

EXTRA_LDFLAGS =
LDFLAGS += $(EXTRA_LDFLAGS)

prefix = /usr/local
sbindir = $(prefix)/sbin
unitdir = $(prefix)/lib/systemd/system
ntpunitdir = $(prefix)/lib/systemd/ntp-units.d

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

all: $(NAME)

clean:
	-rm -rf $(NAME) *.o .deps timedated.h

$(NAME): $(OBJS)

$(NAME).c: timedated.h

timedated.xml:
	gdbus introspect --system --xml --dest org.freedesktop.timedate1 \
		--object-path /org/freedesktop/timedate1 > $@

timedated.h: timedated.xml
	@(echo '#define TIMEDATED_XML \'; \
		sed -e 's|\\|\\\\|g' -e 's|"|\\"|g' -e 's|\(.*\)|\"\0\"\ \\|'; \
		echo) < $^ > $@

install: $(NAME)
	mkdir -p $(sbindir) $(unitdir) $(ntpunitdir)
	install $(NAME) $(sbindir)
	install -p -m 644 $(NAME).service $(unitdir)

.deps:
	@mkdir .deps

.deps/%.d: %.c .deps
	@$(CC) -MM $(CPPFLAGS) -MT '$(<:%.c=%.o) $@' $< -o $@

-include $(OBJS:%.o=.deps/%.d)

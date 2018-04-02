
APP_DIR 	= ./


TARGET=pwdump.exe

all:$(TARGET) 
CC=x86_64-w64-mingw32-gcc
WINDRES =x86_64-w64-mingw32-windres

#STD = -std=c99

WARN   = -w -W -Werror -Wall

INC_DIR = -I./ -I./libssl/include
LIBS    = -L./ -L./libssl/lib
CFLAGS  = $(WARN)  $(INC_DIR) $(OPTION)

ACTION = release

ifeq ($(ACTION),release)
CFLAGS += -O2
else
CFLAGS += -g
endif

#CC_DEF += 

C_RULE_FILE	   = c.rule
######################################################################################### 

#c and cpp file dependence compute rule
%.dcpp: %.cpp
	$(CC) $(CFLAGS) -M $< >> $(DEPS_FILE)
	@cat $(C_RULE_FILE) >> $(DEPS_FILE)

%.dc: %.c
	$(CC) $(CFLAGS) -M $< >> $(DEPS_FILE)
	@cat $(C_RULE_FILE) >> $(DEPS_FILE)

APP_OBJS = utils.o crypt.o samparser.o main.o

#########################################################################################
dep: del_dep $(APP_DEPS)
	@echo building all files dependency done

del_dep:
	@$(RM) $(DEPS_FILE) -rf

#########################################################################################
ifneq ($(wildcard $(DEPS_FILE)),)
	include $(DEPS_FILE)
endif

LDFLAGS=-lssl -lcrypto -Ole32 

$(TARGET):$(APP_OBJS)
	$(CC) $(CFLAGS) $(LIBS) $(APP_OBJS) -o $(TARGET) $(LDFLAGS)


install:
	$(NINS) installer.nsi
clean:
	rm -f *.o $(TARGET) 
	
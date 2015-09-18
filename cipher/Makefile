include ../Makefile.comm

INC += -I../
INC += -I./

SOURCES = $(foreach d,.,$(wildcard $(d)/*.c))
OBJS = $(patsubst %.c, %.o, $(SOURCES))
OBJS += md5key.o

CC += $(SHARED_FLAG)
all : libcipher.a
libcipher.a : $(OBJS)
	ar -rus $@ $^
	echo $(OBJS)
	echo $(SOURCES)
	@echo ""
	@echo "+--------------------------------------------+"
	@echo "|            Finish compilation              |"
	@echo "+--------------------------------------------+"
	@echo "|         Thanks using libcipher.a           |"
	@echo "|   copyright(c)Wang Yaofu  voipman@qq.com   |"
	@echo "+--------------------------------------------+"

clean:
	rm -rf *.o *.a


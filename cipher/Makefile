include ../Makefile.comm

INC += -I../
INC += -I./

SOURCES = $(foreach d,.,$(wildcard $(d)/*.c))
SOURCES += $(foreach d,.,$(wildcard $(d)/*.cpp))
SOURCES += $(foreach d,./aes,$(wildcard $(d)/*.cpp))
OBJS = $(patsubst %.c, %.o, $(SOURCES))
OBJS += $(patsubst %.cpp, %.o, $(SOURCES))

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


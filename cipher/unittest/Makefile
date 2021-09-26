include ../../Makefile.comm
PROJECT = unittest

SRCS  = .
SRCS += ./ut
SRCS += ..
SRCS += ../../base

LIB  = -lstdc++ -lpthread

INC  = -I.
INC += -I..
INC += -I../..

CPP_SRCS = $(foreach d,$(SRCS),$(wildcard $(d)/*.cpp))
C_SRCS   = $(foreach d,$(SRCS),$(wildcard $(d)/*.c))

CPP_OBJS = $(patsubst %.cpp, %.o, $(CPP_SRCS))
C_OBJS = $(patsubst %.c, %.o, $(C_SRCS))

OBJS = $(CPP_OBJS)
OBJS += $(C_OBJS)
all : $(PROJECT)

$(PROJECT) : $(OBJS) $(MODULE)
	$(CC) -o $@ $(OBJS) $(LIB)
	@echo ""
	@echo "+--------------------------------------------+"
	@echo "|      Finish compilation unittest           |"
	@echo "+--------------------------------------------+"
	@echo "|   copyright(c)Wang Yaofu  voipman@qq.com   |"
	@echo "+--------------------------------------------+"

clean:
	rm -rf *.o *.a *_unittest

install :
	test -d ../test || mkdir -p ../test
	cp unittest ../test

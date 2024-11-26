SRCS := $(notdir $(wildcard src/*.c))
OBJS := $(patsubst %.c, %.o, $(SRCS))

INC := include

TARGET := lite-capture

default: $(TARGET)

$(TARGET):$(OBJS)
	gcc -o $@ $^ -lpcap

%.o: src/%.c
	gcc -o2 -c -std=c17 -o $@ $< -I$(INC)

.PHONY :clean
clean:
	rm $(OBJS) $(TARGET)
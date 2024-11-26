APP := ./app/lite-capture
MODULE := ./module/lite_capture.ko

default: $(APP) $(MODULE)

$(APP):
	make -C app

$(MODULE):
	make -C module

.PHONY :clean install uninstall
clean:
	make -C app clean
	make -C module clean

install:
	mkdir -p /usr/lib/lite-capture
	mkdir -p /tmp/lite-capture
	cp $(APP) /usr/bin/
	chmod +x /usr/bin/lite-capture
	cp $(MODULE) /usr/lib/lite-capture/

uninstall:
	rm -rf /usr/lib/lite-capture
	rm -rf /tmp/lite-capture
	rm -f /usr/bin/lite-capture

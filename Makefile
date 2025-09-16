LIBDIR := lib
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update $(CLONE_ARGS) --init
else
	git clone -q --depth 10 $(CLONE_ARGS) \
	    -b main https://github.com/martinthomson/i-d-template $(LIBDIR)
endif

.PHONY: setup setup-ruby setup-editorconfig lint-fix

setup: setup-ruby setup-editorconfig

setup-ruby:
	sudo apt-get install ruby ruby-bundler

setup-editorconfig:
	mkdir -p bin
	curl -L https://github.com/editorconfig-checker/editorconfig-checker/releases/download/v3.4.0/ec-linux-386.tar.gz -o bin/ec-linux-386.tar.gz
	tar -xzf bin/ec-linux-386.tar.gz -C bin
	mv bin/bin/ec-linux-386 bin/editorconfig-checker
	rm -rf bin/bin
	rm bin/ec-linux-386.tar.gz
	chmod +x bin/editorconfig-checker


lint-fix:
	bin/editorconfig-checker draft-ietf-satp-core.md

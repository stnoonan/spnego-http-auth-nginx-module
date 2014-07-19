
NAME=ngx_http_auth_spnego_module
VERSION=1.0.0

NPKG=$(NAME)-$(VERSION)
NHEAD=$(NAME)-HEAD
NCURRENT=$(NAME)-current

GIT-FILES:=$(shell git ls-files | grep -v ChangeLog)
FILES=ChangeLog $(GIT-FILES)

ChangeLog: $(GIT-FILES)
	git log | sed 1d> "$@"

arch-release:
	rm -f ../$(NPKG).tar.gz ../$(NPKG).zip
	scripts/link-files-to .tmp/$(NPKG) $(FILES)
	git log > .tmp/$(NPKG)/ChangeLog
	tar cvzf ../$(NPKG).tar.gz -C .tmp $(NPKG)
	cd .tmp && zip -r ../../$(NPKG).zip $(NPKG)
	rm -rf .tmp

arch-current:
	rm -f ../$(NCURRENT).tar.gz ../$(NCURRENT).zip
	scripts/link-files-to .tmp/$(NCURRENT) $(FILES)
	git log > .tmp/$(NCURRENT)/ChangeLog
	tar cvzf ../$(NCURRENT).tar.gz -C .tmp $(NCURRENT)
	cd .tmp && zip -r ../../$(NCURRENT).zip $(NCURRENT)
	rm -rf .tmp

arch-head:
	rm -f ../$(NNHEAD).tar.gz ../$(NHEAD).zip
	git archive --format=zip --prefix=$(NHEAD)/ HEAD > ../$(NHEAD).zip
	git archive --format=tar --prefix=$(NHEAD)/ HEAD | gzip > ../$(NHEAD).tar.gz

clean:
	rm -f *~

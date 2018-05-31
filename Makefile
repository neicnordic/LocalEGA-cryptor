
REQUIREMENTS=requirements.txt
BUILDDIR=_build
TARGET=$(BUILDDIR)/legacryptor
SRCDIR=legacryptor
INTERPRETER=/usr/bin/env python3


.PHONY: $(TARGET)

all: $(TARGET)

$(TARGET):
	mkdir -p $(TARGET)
	cp -r $(SRCDIR)/* $(TARGET)/.
	python -m pip install -r $(REQUIREMENTS) --target $(TARGET)
	-rm $(TARGET)/.dist-info
	python -m zipapp -p "$(INTERPRETER)" $(TARGET)

#	mv $(TARGET).pyz $@


clean:
	rm -rf $(BUILDDIR)

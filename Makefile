DIR = .
IMAGES = $(shell find $(DIR) -iname '*.png' -type f)
SOURCES = $(shell find $(DIR) -iname '*.md' -type f)
WEBPS = $(patsubst %.png,%.webp,$(IMAGES))
TARGETS = $(patsubst %.md,%.html,$(SOURCES))
MC=./builder

all: $(TARGETS)

%.webp: %.png
	cwebp $< -quiet -q 80 -o $@

%.html: %.md
	$(MC) $< > $@

$(TARGETS): $(WEBPS)

.PHONY: clean clean_images
clean:
	find $(DIR) -iname '*.html' -type f -exec rm -f {} +

clean_images:
	find $(DIR) -iname '*.png' -type f -exec rm -f {} +

regress:
	bin/REGRESS

binary:
	bin/GRAB_BINARY

NEWBENCH=${wildcard OUTPUT_*}
newbench: ${NEWBENCH}
	rm -rf OUTPUTbench.old
	mv OUTPUTbench OUTPUTbench.old
	mv "${NEWBENCH}" OUTPUTbench

all: regress binary

clean:
	rm -rf DIFFS core *.core BINARY_* OUTPUT_* *.xpl

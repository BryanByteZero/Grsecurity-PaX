#!/bin/bash

PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:$PATH"

chpax -v /bin/sh >/dev/null 2>&1 || exit 0

while read -r flag desc; do
  eval "flag_$flag"="\$desc"
done <<'EOF'
P	paging based PAGE_EXEC is enabled|Paging based PAGE_EXEC *: enabled
p	paging based PAGE_EXEC is disabled|Paging based PAGE_EXEC *: disabled
E	trampolines are emulated|Trampolines *: emulated
e	trampolines are not emulated|Trampolines *: not emulated
M	mprotect\(\) is restricted|mprotect\(\) *: restricted
m	mprotect\(\) is not restricted|mprotect\(\) *: not restricted
R	mmap\(\) base is randomized|mmap\(\) base *: randomized
r	mmap\(\) base is not randomized|mmap\(\) base *: not randomized
X	ET_EXEC base is randomized|ET_EXEC base *: randomized
x	ET_EXEC base is not randomized|ET_EXEC base *: not randomized
S	segmentation based PAGE_EXEC is enabled|Segmentation based PAGE_EXEC *: enabled
s	segmentation based PAGE_EXEC is disabled|Segmentation based PAGE_EXEC *: disabled
EOF

if test -r /etc/chpax.cfg; then
  sed -e 's/#.*$//;s/^[ 	]*//;s/[ 	]*$//;/^$/d' /etc/chpax.cfg |
  while read -r flags filename; do
    if test -r "$filename"; then
      f="$filename"
      while test -n "$flags"; do
        newflags="${flags#[^ ]}"
        flag="${flags%$newflags}"
        flags="$newflags"
        eval desc="\$flag_$flag"
        if test -z "$desc"; then
          echo "Invalid flag \"$flag\" for \"$filename\"" >&2
        else
          chpax -v "$filename" 2>&1 | egrep "$desc" >/dev/null 2>&1
          if test "$?" -ne 0; then
            if test -n "$f"; then
              echo "$f"
              f=""
            fi
            echo -n "  ${desc%%|*}"
            ID="~$$~"
            cp -a "$filename" "$filename$ID" >/dev/null 2>&1
            chmod +w "$filename$ID"
            chpax "-$flag" "$filename$ID" >/dev/null 2>&1
            chmod --reference="$filename" "$filename$ID"
            if test -r "$filename$ID"; then
              rm -f "$filename"
              mv "$filename$ID" "$filename"
            fi
            chpax -v "$filename" 2>&1 | egrep "$desc" >/dev/null 2>&1
            if test "$?" -eq 0; then
              echo " (ok)"
            else
              echo " (failed)"
            fi
          fi
        fi
      done
    fi
  done
fi

Userfaultfd is a pretty fast page-fault handler mechanism ... alternative to mprotect/sigsev mechanism.  

## Advantages
1. Pretty fast
1. It is already ported to the mainline kernel and we are able to handle page-faults caused by missing pages (not in TLB).   
2. We can also observe if the page-fault was triggered by a write or a read access.
3. In its developing branch, we can also handle write accesses to mprotected(!PROT_WRITE) pages.
4. We may be able to use it for michrobenchmarks to show how fast we can be in case of some additional engineering.

## Disadvantages
1. We are not able to handle read accesses to mprotected(!PROT_READ) pages.
2. We do not have any context for the read/write access, which we need

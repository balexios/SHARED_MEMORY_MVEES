# SHARED_MEMORY_MVEES
Notes and Ideas about shared memory support for MVEEs

Ideally we would like to be able to intercept reads/writes in a lockstep.  
Consequently, we need the context of the read/write to be able to know what is happening and how the monitor
should treat the case.  

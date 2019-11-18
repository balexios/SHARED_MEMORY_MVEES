/* -*- compile-command: "gcc -Wall -Werror -pthread userfaultfd_test4.c" -*- */
/* Little illustration of userfaultfd. Set up a userfaultfd, mmap two
   pages. Whenever one of those pages is requested, fill it with a specific
   string.
*/
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <linux/userfaultfd.h>

struct thread_args {
	char *memory;
	int fd;
};

#define PAGESIZE 4096

int userfaultfd(int flags)
{
	return syscall(SYS_userfaultfd, flags);
}

void *write_virtual_memory(void *t_a)
{
	sleep(2);
	struct thread_args *args = (struct thread_args *) t_a;
	if (write(args->fd, args->memory, PAGESIZE) != PAGESIZE
	    || write(args->fd, args->memory + PAGESIZE, PAGESIZE) != PAGESIZE) {
		fprintf(stderr, "++ write failed: %m\n");
	}
	return NULL;
}

int main (int argc, char **argv)
{
	int return_code = 0;
	int fd = 0;
	int sockets[2] = {0};

	if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets)) {
		fprintf(stderr, "++ socketpair failed: %m\n");
		goto cleanup_error;
	}

	if ((fd = userfaultfd(O_NONBLOCK)) == -1) {
		fprintf(stderr, "++ userfaultfd failed: %m\n");
		goto cleanup_error;
	}
	/* When first opened the userfaultfd must be enabled invoking the
	   UFFDIO_API ioctl specifying a uffdio_api.api value set to UFFD_API
	   (or a later API version) which will specify the read/POLLIN protocol
	   userland intends to speak on the UFFD and the uffdio_api.features
	   userland requires. The UFFDIO_API ioctl if successful (i.e. if the
	   requested uffdio_api.api is spoken also by the running kernel and the
	   requested features are going to be enabled) will return into
	   uffdio_api.features and uffdio_api.ioctls two 64bit bitmasks of
	   respectively all the available features of the read(2) protocol and
	   the generic ioctl available. */
	struct uffdio_api api = { .api = UFFD_API };
	if (ioctl(fd, UFFDIO_API, &api)) {
		fprintf(stderr, "++ ioctl(fd, UFFDIO_API, ...) failed: %m\n");
		goto cleanup_error;
	}
	/* "Once the userfaultfd has been enabled the UFFDIO_REGISTER ioctl
	   should be invoked (if present in the returned uffdio_api.ioctls
	   bitmask) to register a memory range in the userfaultfd by setting the
	   uffdio_register structure accordingly. The uffdio_register.mode
	   bitmask will specify to the kernel which kind of faults to track for
	   the range (UFFDIO_REGISTER_MODE_MISSING would track missing
	   pages). The UFFDIO_REGISTER ioctl will return the uffdio_register
	   . ioctls bitmask of ioctls that are suitable to resolve userfaults on
	   the range registered. Not all ioctls will necessarily be supported
	   for all memory types depending on the underlying virtual memory
	   backend (anonymous memory vs tmpfs vs real filebacked mappings)." */
	if (api.api != UFFD_API) {
		fprintf(stderr, "++ unexepcted UFFD api version.\n");
		goto cleanup_error;
	}
	/* mmap some pages, set them up with the userfaultfd. */
	void *pages = NULL;
	if ((pages = mmap(NULL, PAGESIZE * 2, PROT_READ,
			  MAP_PRIVATE | MAP_ANONYMOUS, 0, 0)) == MAP_FAILED) {
		fprintf(stderr, "++ mmap failed: %m\n");
		goto cleanup_error;
	}
	struct uffdio_register reg = {
		.mode = UFFDIO_REGISTER_MODE_MISSING,
		.range = {
			.start = (long) pages,
			.len = PAGESIZE * 2
		}
	};
	if (ioctl(fd, UFFDIO_REGISTER,  &reg)) {
		fprintf(stderr, "++ ioctl(fd, UFFDIO_REGISTER, ...) failed: %m\n");
		goto cleanup_error;
	}
	if (reg.ioctls != UFFD_API_RANGE_IOCTLS) {
		fprintf(stderr, "++ unexpected UFFD ioctls.\n");
		goto cleanup_error;
	}
	/* start a thread that will fault... */
	pthread_t thread = {0};
	if (pthread_create(&thread, NULL, write_virtual_memory,
			   & (struct thread_args) {
				   .memory = pages,
				   .fd = sockets[1]
			   })) {
		fprintf(stderr, "++ pthread_create failed: %m\n");
		goto cleanup_error;
	}

	/* and then wait for the faults to happen. */
	char data[PAGESIZE] = "-- handled page fault.\n";
	struct pollfd evts[2] = {
		{ .fd = fd, .events = POLLIN },
		{ .fd = sockets[0], .events = POLLIN }
	};
	while (poll(evts, sizeof(evts) / sizeof(struct pollfd), 5000) > 0) {
		/* unexpected poll events */
		if (evts[0].revents & POLLERR
		    || evts[1].revents & POLLERR) {
			fprintf(stderr, "++ POLLERR\n");
			goto cleanup_error;
		} else if (evts[0].revents & POLLHUP
			   || evts[1].revents & POLLHUP) {
			fprintf(stderr, "++ POLLHUP\n");
			goto cleanup_error;
		}		
		/* handle the userfaultfd data */
		if (evts[0].revents & POLLIN) {
			struct uffd_msg fault_msg = {0};
			if (read(fd, &fault_msg, sizeof(fault_msg)) != sizeof(fault_msg)) {
				fprintf(stderr, "++ read failed: %m\n");
				goto cleanup_error;
			}
			char *place = (char *)fault_msg.arg.pagefault.address;
			if (fault_msg.event != UFFD_EVENT_PAGEFAULT
			    || (place != pages && place != pages + PAGESIZE)) {
				fprintf(stderr, "unexpected pagefault?.\n");
				goto cleanup_error;
			}
			struct uffdio_copy copy = {
				.dst = (long) place,
				.src = (long) data,
				.len = PAGESIZE
			};
			if (ioctl(fd, UFFDIO_COPY, &copy)) {
				fprintf(stderr, "++ ioctl(fd, UFFDIO_COPY, ...) failed: %m\n");
				goto cleanup_error;
			}
		}
		/* handle the child thread's data */
		if (evts[1].revents & POLLIN) {
			char msg[PAGESIZE] = {0};
			if (read(sockets[0], &msg, sizeof(msg)) == -1) {
				fprintf(stderr, "++ read failed: %m\n");
				goto cleanup_error;
			}
			printf("%s", msg);
		}
	}
	goto cleanup;
cleanup_error:
	return_code = 1;
cleanup:
	if (fd) close(fd);
	if (sockets[0]) close(sockets[0]);
	if (sockets[1]) close(sockets[1]);
	return return_code;
}

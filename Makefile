CC = gcc
CFLAGS = -Wall -Wextra -Werror

user: user.c
	$(CC) $(CFLAGS) user.c -o user

clean:
	rm -f user
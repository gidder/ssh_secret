import argparse
import asyncio
import asyncssh
import sys

from secret_helper import async_secret


async def run_client(host, args):
    async with asyncssh.connect(host, **args,
                                # kex_algs=("diffie-hellman-group14-sha256",),
                                # compression_algs=None,
                                # encryption_algs=("aes128-ctr",),
                                ) as conn:
        result = await conn.run('ls /', check=True)
        print(result.stdout, end='')


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Connect to SSH and save connection secret key.')
    parser.add_argument('host')
    parser.add_argument('username', nargs='?')
    parser.add_argument('password', nargs='?')

    args = parser.parse_args()
    args_dict = {}

    for attr in dir(args):
        if attr[0] == '_':
            continue
        if attr != 'host' and getattr(args, attr) is not None:
            args_dict[attr] = getattr(args, attr)

    try:
        with async_secret():
            asyncio.get_event_loop().run_until_complete(run_client(args.host, args_dict))
    except (OSError, asyncssh.Error) as exc:
        sys.exit('SSH connection failed: ' + str(exc))

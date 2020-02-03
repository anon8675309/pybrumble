#!/usr/bin/env python3
from logging import basicConfig, DEBUG, INFO, WARNING, ERROR, CRITICAL

def setup_logging(args):
	if args.verbose:
		level = DEBUG if args.verbose > 1 else INFO
	elif args.quiet:
		level = CRITICAL if args.quiet > 1 else ERROR
	else:
		level = WARNING
	basicConfig(level=level, format='[%(levelname)7s] %(asctime)s - %(message)s')

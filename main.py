
import argparse
import threading
import os
import sys
sys.stderr = None
from examples import conf9, conf8, conf7, conf6, conf5, conf4, conf3, conf2, conf1
import tools

sys.stderr = sys.__stderr__


def get_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", type=int, help="Configuration to run (1 - 9)")
    group.add_argument("-s", action='store_true', help="Display info on configurations available")

    parser.add_argument("-d", type=int, default=1, help="Debug level (0 - 9)")
    parser.add_argument("-t", type=int, default=180, help="Time to execute simulation")

    return parser.parse_args()


args = get_args()

tools.debug_level = args.d

if args.s:
    print("Configuration 1. Two routers, the simplest configuration.")
    print("Configuration 2. Three interconnected routers.")
    print("Configuration 3. Three interconnected routers, one goes on and off every 43 and 85 seconds.")
    print("Configuration 4. Ring of 4 routers.")
    print("Configuration 5. Arbitrary configuration of 6 router with router 502 going offline after 40 sec.")
    print("Configuration 6. Twelve randomly connected routers. Router 502 goes offline after first 30 seconds of work.")
    print("Configuration 7. Two routers pinging each other.")
    print("Configuration 8. Two routers (501, 502) pinging each other through a medium BGP router 502.")
    print("Configuration 9. Twelve randomly connected routers. Some pinging each other.")
    exit()
else:
    c = args.c
    if c == 1:
        conf1(args.t)
    elif c == 2:
        conf2(args.t)
    elif c == 3:
        conf3(args.t)
    elif c == 4:
        conf4(args.t)
    elif c == 5:
        conf5(args.t)
    elif c == 6:
        conf6(args.t)
    elif c == 7:
        conf7(args.t)
    elif c == 8:
        conf8(args.t)
    elif c == 9:
        conf9(args.t)



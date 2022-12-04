#!/usr/bin/env python

import time


def get_input_and_write(fname):
    inpt = input('action name: ')
    ts = time.time()
    print(ts)
    with open(fname, mode="a") as f:
        f.write(f"{time.time()},{inpt}\n")


def main():
    csv_file = "timestamp_to_action.csv"
    with open(csv_file, mode="w") as f:
        f.write("timestamp,action_name\n")
    try:
        while True:
            get_input_and_write(csv_file)
    except KeyboardInterrupt:
        print("\n\nexited...")


if __name__ == '__main__':
    main()

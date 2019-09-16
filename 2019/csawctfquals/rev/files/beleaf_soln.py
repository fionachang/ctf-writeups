#!/bin/python

def read_file(filename):
    with open(filename) as f:
        contents = f.read()

    return contents


def parse_char_positions(data):
    return [int(data[idx:idx+2], 16) for idx in xrange(0, len(data), 16)]


def parse_charset(data):
    return [data[idx:idx+2].decode("hex") for idx in xrange(0, len(data), 8)]


def main():
    dat_003014e0 = read_file("dat_003014e0.txt")
    char_positions = parse_char_positions(dat_003014e0)
    dat_00301020 = read_file("dat_00301020.txt")
    charset = parse_charset(dat_00301020)
    flag = []

    for char_position in char_positions:
        flag.append(charset[char_position])

    print "".join(flag)


if __name__ == "__main__":
    main()

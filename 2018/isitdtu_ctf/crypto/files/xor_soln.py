#!/bin/python

def user_guess(flag, key):
    choice = raw_input("Update flag or key? ").lower()

    if choice not in ["flag", "key"]:
        print "Error: Invalid choice"
        return False

    idx = int(raw_input("Update at which index? ")) 
    value = raw_input("What will be the new value? ")

    try:
        locals()[choice][idx] = value
    except IndexError as e:
        print "Error: {}".format(e)
        return False

    return True

def main():
    flag_pre = "ISITDTU{"
    flag_padding = " "
    len_key = 10
    enc_flag = "1d14273b1c27274b1f10273b05380c295f5f0b03015e301b1b5a293d063c62333e383a20213439162e0037243a72731c22311c2d261727172d5c050b131c433113706b6047556b6b6b6b5f72045c371727173c2b1602503c3c0d3702241f6a78247b253d7a393f143e3224321b1d14090c03185e437a7a607b52566c6c5b6c034047"
    key = [None] * len_key
    m = []

    for i in xrange(0, len(enc_flag), 2):
        m.append(int(enc_flag[i:i+2], 16))

    flag = [None] * len(m)

    for idx, i in enumerate(flag_pre):
        flag[idx] = i

    # Guesses
    # flag[-1] = "}"
    # key[1] = "o"

    updated = True

    while updated and None in flag:
        updated = True

        while updated and None in flag:
            updated = False
            m_idx = 0

            for a in range(len_key):
                i = a

                for b in range(len(m)/len_key):
                    if b % 2 != 0:
                        if not flag[i] and key[a]:
                            flag[i] = chr(m[m_idx] ^ ord(key[a]))
                            updated = True
                        elif not key[a] and flag[i]:
                            key[a] = chr(m[m_idx] ^ ord(flag[i]))
                            updated = True
                    else:
                        flag_idx = i + len_key - (a+1+a)

                        if not key[a] and flag[flag_idx]:
                            key[a] = chr(m[m_idx] ^ ord(flag[flag_idx]))
                            updated = True
                        elif not flag[flag_idx] and key[a]:
                            flag[flag_idx] = chr(m[m_idx] ^ ord(key[a]))
                            updated = True

                    i += len_key
                    m_idx += 1

        print "flag: {}".format("".join(c if c else "?" for c in flag))
        print "key: {}".format("".join(c if c else "?" for c in key))

        if not updated:
            if user_guess(flag, key):
                updated = True
            else:
                print "Aborted"


if __name__ == "__main__":
    main()

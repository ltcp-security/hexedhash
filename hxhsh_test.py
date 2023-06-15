#
# HexedHash algorithm
# Developed by "LTCP Security"
# MIT License
#

class Hasher:
    def __init__(self, prefix: str | None = "ltcp", salt: str | None = "ltcp_security"):
        self.prefix = prefix
        self.salt = salt

    def __makehex(self, text: str | None = "None") -> str:
        print(self.salt)
        print(Hasher.__makehex, text)
        corsalt = []
        for s in range(len(self.salt)):
            corsalt.append(str(hex(ord(self.salt[s]))))
            print("s cycle: index[" + str(s) + "] corsalt: " + corsalt)
        toreturn = ""
        for a in range(len(text)):
            toreturn += corsalt[a % len(corsalt)] + str(hex(ord(text[a])))
            print("a cycle: index[" + str(a) + "] toreturn: " + toreturn)
        toreturn = toreturn.replace("0x", "")
        if len(toreturn) % 2 != 0:
            toreturn += "0"
        return toreturn

    def makehash(self, text: str | None = "None") -> str:
        donehex = Hasher(salt=self.salt, prefix=self.prefix).__makehex(text = text)
        print("Hex size:", len(donehex))
        delcount = (len(donehex) - 16) // 2
        print("Deleting: " + str(delcount * 2) + " symbols")
        print((0 - len(donehex) - delcount))
        doneHash = donehex[0 - (len(donehex) - delcount):len(donehex) - delcount]
        print(len(doneHash))

        return doneHash
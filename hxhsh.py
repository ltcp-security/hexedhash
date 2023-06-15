#
# HexedHash algorithm
# Developed by "LTCP Security"
# https://github.com/ltcp-security
#

class Hasher:
    def __init__(self, prefix: str | None = "ltcp", salt: str | None = "ltcp_security"):
        self.prefix = prefix
        self.salt = salt

    def __makehex(self, text: str | None = "None") -> str:
        corsalt = []
        for s in range(len(self.salt)):
            corsalt.append(str(hex(ord(self.salt[s]))))
        toreturn = ""
        for a in range(len(text)):
            toreturn += corsalt[a % len(corsalt)] + str(hex(ord(text[a])))
        toreturn = toreturn.replace("0x", "")
        if len(toreturn) % 2 != 0:
            toreturn += "0"
        return toreturn

    def makehash(self, text: str | None = "None") -> str:
        donehex = Hasher(salt=self.salt, prefix=self.prefix).__makehex(text = text)
        delcount = (len(donehex) - 16) // 2
        doneHash = donehex[0 - (len(donehex) - delcount):len(donehex) - delcount]
        return f"{self.prefix}[{doneHash}]"
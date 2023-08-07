# osscan (OSRS packet ID dumper)

this program can be used to automatically update all server-to-client packet ID for OldSchool Runescape for any revision 

after scanning and descrambling the packet table in the game client (using the Steam version of the game), the tool will report back a list of packets in the same order regardless of revision with the correct ID for the revision

## compile

```bash
  gcc osscan.c -o osscan
```
    
## usage/examples
the program takes the path to the OSRS client (steam version) and returns an ordered list of IDs for that revision corresponding to the same packets.

**REVISION 213:**

for reference, 
the packet ID for packet "*REBUILD_NORMAL* " is **0** in this revision.

```bash
./osscan osclient_213.exe

output:
...
...
>descrambled table:
---------------
    000 042 065 003 069 072 007 024 048 090 014 061 093 035 027 021 
    070 037 085 017 008 091 004 028 075 074 053 056 082 023 046 025 
    019 066 089 101 106 099 117 005 030 010 052 047 044 083 015 068 
    100 020 079 094 102 067 063 034 062 036 064 076 098 103 071 032 
    088 111 108 109 110 112 012 018 059 043 057 040 058 051 033 002 
    113 114 115 116 054 022 080 081 049 097 045 107 001 013 105 031 
    016 078 050 026 096 092 086 009 077 039 038 011 041 095 006 104 
    055 060 029 084 073 087 
---------------
total packet: 118
```
The order never changes and the first packet in the table is always "REBUILD_NORMAL", which as we can see has correctly been identified as ID 0.

**REVISION 214:**

for reference, the packet ID for packet *"REBUILD_NORMAL*" is **70** in this revision.

```bash
./osscan osclient_214.exe

output:
...
...
>descrambled table:
---------------
    070 034 014 056 023 004 103 080 006 040 033 072 059 101 089 065 
    100 022 026 025 099 016 043 024 068 027 041 048 096 091 020 112 
    114 051 019 009 012 037 081 042 075 030 061 116 001 102 064 035 
    115 045 090 098 054 036 092 007 031 021 069 087 083 095 062 082 
    108 079 013 047 005 039 085 044 011 071 107 060 063 111 109 066 
    073 000 029 003 055 088 113 032 097 049 067 018 052 046 084 057 
    008 050 086 106 010 002 105 077 038 076 053 093 094 104 028 078 
    058 015 110 074 017 
---------------
total packet: 117
```
again, since we expect *"REBUILD_NORMAL*" to be first in the table, we can see it has correctly descrambled the ID as **70**

**REVISION 215:**

for reference, the packet ID for packet *REBUILD_NORMAL* is **99** in this revision.

```bash
./osscan osclient_215.exe

output:
...
...
>descrambled table:
---------------
    099 054 048 101 100 004 003 079 056 067 028 115 073 057 083 021 
    086 076 039 008 089 045 118 119 120 078 052 040 029 043 023 041 
    044 062 065 047 055 000 051 038 032 070 022 007 075 066 074 019 
    018 077 025 091 088 063 096 093 117 105 015 068 087 081 108 064 
    024 097 006 082 103 104 012 013 061 002 037 109 014 060 058 026 
    114 111 116 069 049 080 030 090 009 095 072 053 050 046 005 020 
    106 059 027 017 011 042 094 102 034 084 112 036 113 016 031 110 
    071 092 001 010 107 098 035 033 085 
---------------
total packet: 121
```

## ORDER OF PACKETS / information

- the tool should continue to work through any revision update  as long as there is no large updates that break any signatures which could prevent the table from being found and descrambled. the tool would require an update in this situation
- the order of packets always remains the same but when a new packet is added or an old one removed, the order of packets will end up shifting over 1 depending on where the new packet was added or removed along the list so keep that in mind.
- i provide a file with name *ORDER.txt* which is a partial list of the names of the packets in the table according to their order which is based on 214 so keeping in mind that the order might have shifted a slot or two in some areas depending on where any new packet was added since 214.
- since 99% of the order does not change, you can always use the same order list for reference and make whatever change or addition needed as more packets are added to the game or as you discover and put more names to IDs,  because we have UNKNOWN packets.

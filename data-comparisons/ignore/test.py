#!/usr/bin/python
import math
import json


# joda-time

#==========================
#========== MAIN ==========
#==========================
if __name__ == "__main__":


    stuff = ":hello@1.2.3"
    if stuff[0] == ":":
        stuff = "@" + stuff[0 + 1:]
    print(stuff)

    # listA = ["joda-time:joda-time:2.9.5"]
    # listB = ["org.jruby:joda-timezones:2013d",
    #         "joda-time:joda-time:2.9.4",
    #         "joda-time:joda-time:2.3",
    #         "joda-time:joda-time:2.8.1",
    #         "joda-time:joda-time:1.6",
    #         "joda-time:joda-time:2.9.5"]

    # found = True
    # for i in listA:
    #     #Get levels 
    #     for s in reversed(range(11)):
    #         if s > 2 and found == False:
    #             matching = math.floor(len(i)-(len(i)/s))
    #             substring = i[0:matching]
    #             print(substring)
    #             for j in listB:
    #                 if i != j:
    #                     if substring in j:
    #                         print("LEVEL ",s," \t",i," ~= ", j)
    #                         found = True
    #                         break

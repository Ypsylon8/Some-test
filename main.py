from base64 import b64decode, b64encode
import keep_alive
from requests import post
from random import choice, randint
from itertools import cycle
from hashlib import sha1
from time import sleep
from threading import Thread
from uuid import uuid4

print(
  "Welcome to Like- and Rate/View-bot [Type 'help' for help] (Released on ...) -Rylixmods"
)


def xor(data, key):
  xored = ''.join(chr(ord(x) ^ ord(y)) for (x, y) in zip(data, cycle(key)))
  return b64encode(xored.encode())


def unxor(xored, key):
  data = b64decode(xored.encode()).decode()
  unxored = ''.join(chr(ord(x) ^ ord(y)) for (x, y) in zip(data, cycle(key)))
  return unxored


head = {
  'Accept-Encoding': None,
  'User-Agent': "",
  'Accept': '*/*',
  'Accept-Language': None,
  'Content-Length': '82',
  'Content-Type': 'application/x-www-form-urlencoded'
}

gjp = "RV5DU1hQWAQDBgAG"

keep_alive.keep_alive()

accountidslist = [
  "22647842", "22647885", "22647897", "22647918", "22647934", "22647940",
  "22647952", "22647964", "22647975", "22647987", "22647998", "22648017",
  "22648033", "22662801", "22662824", "22662848", "22662876", "22662901",
  "22662926", "22662937", "22662957", "22662975", "22662999", "22663016",
  "22663036", "22663070", "22663097", "22663445", "22663456", "22663479",
  "22663915", "22663932", "22663954", "22663969", "22664288", "22664296",
  "22664314", "22664334", "22664338", "22664364", "22664374", "22664384",
  "22664395", "22664404", "22664412", "22664459", "22664470", "22664482",
  "22664494", "22664506", "22696702", "22696849", "22696892", "22696965",
  "22697037", "22697108", "22700834", "22700850", "22700896", "22702068",
  "22702093", "22702157", "22702179", "22702209", "22702247", "22702279",
  "22702311", "22702354", "22702378", "22702403", "22702428", "22702558",
  "22702636", "22702661", "22702674", "22702690", "22702711", "22702728",
  "22702760", "22702779", "22702788", "22702863", "22702883", "22702909",
  "22702919", "22702937", "22702961", "22702975", "22702993", "22703015",
  "22703031", "22703062", "22703079", "22703089", "22703104", "22703135",
  "22703147", "22703159", "22703178", "22703198", "23478298", "23478313",
  "23502125", "23502135", "23502144", "23502159", "23502165", "23502176",
  "23502187", "23502192", "23505926", "23505932", "23505935", "23505945",
  "23505955", "23505962", "23505987", "23505989", "23505994", "23506013",
  "23506021", "23506025", "23506078", "23592265", "23592269", "23592283"
]

useridslist = [
  "202577420", "202577741", "202577828", "202577963", "202578028", "202578082",
  "202578170", "202578251", "202578327", "202578383", "202578463", "202578544",
  "202578664", "202691890", "202692033", "202692238", "202692401", "202692547",
  "202692701", "202692800", "202692931", "202693046", "202693184", "202693303",
  "202693402", "202693620", "202693769", "202696006", "202696082", "202696251",
  "202698730", "202698824", "202698897", "202698982", "202700956", "202701021",
  "202701130", "202701208", "202701264", "202701388", "202701447", "202701558",
  "202701642", "202701714", "202701789", "202702130", "202702205", "202702288",
  "202702381", "202702439", "202928599", "202929611", "202929898", "202930352",
  "202930837", "202931373", "202958305", "202958626", "202958764", "202967178",
  "202967289", "202967684", "202967801", "202967949", "202968143", "202968358",
  "202968536", "202968822", "202968940", "202969161", "202969380", "202970366",
  "202970953", "202971094", "202971176", "202971317", "202971417", "202971560",
  "202971729", "202971862", "202971954", "202972425", "202972481", "202972632",
  "202972733", "202972844", "202973012", "202973142", "202973227", "202973320",
  "202973407", "202973643", "202973763", "202973895", "202973991", "202974193",
  "202974275", "202974361", "202974536", "202974637", "208918541", "208918645",
  "209111150", "209111192", "209111253", "209111313", "209111375", "209111421",
  "209111502", "209111546", "209139942", "209140007", "209140037", "209140110",
  "209140171", "209140213", "209140464", "209140514", "209140580", "209140767",
  "209140833", "209140877", "209141352", "209822183", "209822238", "209822307"
]

while (True):
    if 1 == 1:
      try:
        levelid = 82847645
      except:
        pass
      if 1 == 2:
        continue
      else:

        print()
        print("Starting...")
        print()
        proxylist = []
        oldproxies = []
        counter_counter = []
        expired_accids = []
        expired_udids = []

        o = 0

        with open("http.txt", "r") as f:
          for i in f:
            proxylist.append({'http': i})

        counter = 1

        def viewbot(accountid, userid):

          global oldproxies
          global o
          global counter
          global proxylist
          global expired_accids
          global gjp
          global expired_udids
          global levelid

          proxy = choice(proxylist)

          if proxy in oldproxies:
            pass
          else:

            type_ = "1"
            rs = "".join(
              choice(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"
              ) for i in range(10))
            salt = "xI25fpAapCQg"
            levelid = str(levelid)
            while (True):
              udid = str(uuid4())
              if udid in expired_udids:
                continue
              else:
                break
            url = "http://www.boomlings.com/database/downloadGJLevel22.php"
            m = sha1(f"{levelid}1{rs}{accountid}{udid}{userid}{salt}".encode()
                     ).hexdigest()
            x = xor(m, "41274").decode()
            r = "gameVersion=20&binaryVersion=35&gdw=0&accountID=" + accountid + "&gjp=" + gjp + "&udid=" + udid + "&uuid=" + userid + "&levelID=" + levelid + "&inc=1&extras=0&secret=Wmfd2893gb7&rs=" + rs + "&chk=" + x

            try:
              data = post(url=url,
                          data=r,
                          headers=head,
                          proxies=proxy,
                          timeout=10).content.decode()

              if data.startswith("1"):
                print(str(counter) + " | Successfully sent view...")
                if counter in counter_counter:
                  counter += 1
                  pass
                else:
                  counter_counter.append(counter)
                  counter += 1
              elif data == "-1":
                expired_udids.append(udid)
              else:
                pass
            except Exception as e:
              pass

        while (True):
          try:
            randomi1 = choice(accountidslist)
          except Exception as e:
            break
          randomi2 = choice(useridslist)
          t = Thread(target=viewbot, args=(randomi1, randomi2))
          t.daemon = True
          try:
            t.start()
          except:
            continue
